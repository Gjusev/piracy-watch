"""Tests for the fetcher and the GitHub client.

Transport is stubbed except for the redirect-policy and deadline tests,
which run tiny local HTTP servers on 127.0.0.1 (no external network).
"""

import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

from piracy_watch.fetch import FetchError, Fetcher, GithubClient, RateLimited, _SafeRedirectHandler


class FakeFetcher:
    """Duck-typed Fetcher returning queued (status, json-object) responses."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls: list[str] = []

    def get_json(self, url, headers=None):
        self.calls.append(url)
        if not self.responses:
            return 200, {}
        return self.responses.pop(0)


class TestGithubClient(unittest.TestCase):
    def test_successful_search(self):
        items = [{"html_url": "https://github.com/a/b/blob/x"}]
        client = GithubClient(FakeFetcher([(200, {"items": items})]), token="tok")
        result = client.search_code('"sig"')
        self.assertEqual(result, items)
        self.assertEqual(client.queries_used, 1)

    def test_token_sent_in_auth_header(self):
        seen_headers = {}

        class Recording(FakeFetcher):
            def get_json(self, url, headers=None):
                seen_headers.update(headers or {})
                return super().get_json(url, headers)

        client = GithubClient(Recording([(200, {"items": []})]), token="secret-token")
        client.search_repositories("WidgetPro crack")
        self.assertEqual(seen_headers.get("Authorization"), "Bearer secret-token")
        self.assertEqual(seen_headers.get("X-GitHub-Api-Version"), "2022-11-28")

    def test_rate_limit_then_success(self):
        # First call: search returns 403. Second: rate_limit check says the
        # window resets in ~10s (within the wait budget). Third: succeeds.
        import time

        reset = int(time.time()) + 10
        client = GithubClient(
            FakeFetcher([(403, {}), (200, {"resources": {"search": {"reset": reset}}}), (200, {"items": [1]})]),
            token="t",
            sleeper=lambda s: None,
            max_rate_limit_wait_s=60,
        )
        result = client.search_code('"sig"')
        self.assertEqual(result, [1])

    def test_rate_limit_far_future_raises(self):
        import time

        client = GithubClient(
            FakeFetcher([(403, {}), (200, {"resources": {"search": {"reset": int(time.time()) + 999}}})]),
            token="t",
            sleeper=lambda s: None,
            max_rate_limit_wait_s=60,
        )
        with self.assertRaises(RateLimited):
            client.search_code('"sig"')

    def test_server_error_retried_once(self):
        responses = [(500, {}), (200, {"items": []})]
        client = GithubClient(FakeFetcher(responses), token="t", sleeper=lambda s: None)
        self.assertEqual(client.search_code('"sig"'), [])

    def test_client_error_raises_fetch_error(self):
        client = GithubClient(FakeFetcher([(400, {"message": "bad"}), (400, {"message": "bad"})]), token="t")
        with self.assertRaises(FetchError):
            client.search_code('"sig"')

    def test_local_budget_exhausted(self):
        responses = [(200, {"items": []})] * 35
        client = GithubClient(FakeFetcher(responses), token="t", sleeper=lambda s: None)
        for _ in range(30):
            client.search_code('"sig"')
        with self.assertRaises(RateLimited):
            client.search_code('"sig"')
        self.assertEqual(client.queries_left(), 0)

    def test_malformed_payload_raises(self):
        client = GithubClient(FakeFetcher([(200, "not-a-dict")]), token="t")
        with self.assertRaises(FetchError):
            client.search_code('"sig"')


class TestFetcherGuards(unittest.TestCase):
    def test_non_http_url_refused(self):
        fetcher = Fetcher()
        with self.assertRaises(FetchError):
            fetcher.get("file:///etc/passwd")

    def test_read_capped_truncates(self):
        class Stream:
            def __init__(self):
                self.chunks = [b"x" * 65536] * 100  # ~6.5 MB

            def read(self, n):
                return self.chunks.pop(0) if self.chunks else b""

        fetcher = Fetcher(max_bytes=200_000)
        body = fetcher._read_capped(Stream())
        self.assertLessEqual(len(body), 200_000 + 65536)


def _free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _serve(handler_class: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, int]:
    server = HTTPServer(("127.0.0.1", _free_port()), handler_class)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


class _Redirector(BaseHTTPRequestHandler):
    """Redirects every request to the fixed host/port set by the test."""

    target = ""  # e.g. "http://127.0.0.1:8472/final"

    def do_GET(self):
        self.send_response(302)
        self.send_header("Location", self.target)
        self.end_headers()

    def log_message(self, *a):
        pass


class _Recorder(BaseHTTPRequestHandler):
    """Records whether it was hit and with which Authorization header."""

    hits: list[dict] = []

    def do_GET(self):
        _Recorder.hits.append({"path": self.path, "auth": self.headers.get("Authorization")})
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"items": []}')

    def log_message(self, *a):
        pass


class _SameHostRedirector(BaseHTTPRequestHandler):
    """Redirects /redirected → /final on the same host (relative Location)."""

    def do_GET(self):
        if self.path == "/redirected":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.end_headers()
        else:
            _Recorder.hits.append({"path": self.path, "auth": self.headers.get("Authorization")})
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"final")

    def log_message(self, *a):
        pass


class TestRedirectPolicy(unittest.TestCase):
    """MOK-46 F2: the Authorization header must never cross hosts via redirect."""

    def setUp(self):
        _Recorder.hits = []
        self.redirect_server, self.redirect_port = _serve(_Redirector)
        self.target_server, self.target_port = _serve(_Recorder)

    def tearDown(self):
        self.redirect_server.shutdown()
        self.target_server.shutdown()

    def test_cross_host_redirect_is_refused_and_leaks_nothing(self):
        _Redirector.target = f"http://127.0.0.1:{self.target_port}/final"
        fetcher = Fetcher(timeout_s=5)
        status, _ = fetcher.get(
            f"http://127.0.0.1:{self.redirect_port}/search",
            headers={"Authorization": "Bearer ghp_SUPERSECRET"},
        )
        # The redirect surfaces as a normal status; the target is never hit.
        self.assertEqual(status, 302)
        self.assertEqual(_Recorder.hits, [])

    def test_same_host_redirect_is_followed(self):
        server, port = _serve(_SameHostRedirector)
        self.addCleanup(server.shutdown)
        fetcher = Fetcher(timeout_s=5)
        status, body = fetcher.get(
            f"http://127.0.0.1:{port}/redirected",
            headers={"Authorization": "Bearer ghp_LOCALONLY"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"final")
        self.assertEqual(_Recorder.hits[0]["path"], "/final")
        self.assertEqual(_Recorder.hits[0]["auth"], "Bearer ghp_LOCALONLY")  # same host is fine

    def test_handler_refuses_cross_host(self):
        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://api.github.com/search")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(
                req, None, 302, "Found", {"Location": "https://evil.example/final"},
                "https://evil.example/final",
            )
        self.assertIn("cross-host", str(ctx.exception))

    def test_handler_refuses_https_to_http_downgrade(self):
        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://api.github.com/search")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(
                req, None, 302, "Found", {"Location": "http://api.github.com/search"},
                "http://api.github.com/search",
            )
        self.assertIn("https→http", str(ctx.exception))

    def test_handler_refuses_non_http_scheme(self):
        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://api.github.com/search")
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            handler.redirect_request(
                req, None, 302, "Found", {"Location": "ftp://api.github.com/search"},
                "ftp://api.github.com/search",
            )
        self.assertIn("non-http(s)", str(ctx.exception))

    def test_handler_follows_same_host_https(self):
        handler = _SafeRedirectHandler()
        req = urllib.request.Request("https://api.github.com/search")
        request = handler.redirect_request(
            req, None, 302, "Found", {"Location": "https://api.github.com/search/2"},
            "https://api.github.com/search/2",
        )
        self.assertEqual(request.full_url, "https://api.github.com/search/2")


class _Dripper(BaseHTTPRequestHandler):
    """Sends a big Content-Length but trickles a few bytes, one per interval."""

    drip_s = 0.4

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "655360")
        self.end_headers()
        for _ in range(30):
            try:
                self.wfile.write(b"x")
                self.wfile.flush()
            except Exception:
                return
            time.sleep(self.drip_s)

    def log_message(self, *a):
        pass


class TestTotalDeadline(unittest.TestCase):
    """MOK-46 F3: a slow-drip body must not outlive the total deadline."""

    def test_slow_drip_body_stops_at_deadline(self):
        server, port = _serve(_Dripper)
        self.addCleanup(server.shutdown)
        fetcher = Fetcher(timeout_s=1)  # total deadline = 2s
        start = time.monotonic()
        _, body = fetcher.get(f"http://127.0.0.1:{port}/")
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 3.5)
        # Body truncated well short of the advertised 655360 bytes.
        self.assertLess(len(body), 20)

    def test_read_capped_deadline_with_trickling_stream(self):
        class Trickler:
            def __init__(self):
                self.chunks_sent = 0

            def read1(self, n):
                time.sleep(0.3)
                self.chunks_sent += 1
                return b"x" * 100

        fetcher = Fetcher(max_bytes=1_000_000, total_timeout_s=1)
        stream = Trickler()
        body = fetcher._read_capped(stream)
        self.assertLess(len(body), 500)  # deadline stopped the read early
        self.assertLess(stream.chunks_sent, 10)

    def test_total_timeout_defaults_to_double_socket_timeout(self):
        self.assertEqual(Fetcher(timeout_s=1).total_timeout_s, 2)
        self.assertEqual(Fetcher(timeout_s=15).total_timeout_s, 30)
        self.assertEqual(Fetcher(timeout_s=15, total_timeout_s=5).total_timeout_s, 5)


class TestApiSchemeGuard(unittest.TestCase):
    def test_non_https_api_url_refused(self):
        client = GithubClient(FakeFetcher([]), token="tok")
        client.API = "http://api.github.com"
        with self.assertRaises(FetchError):
            client.search_code('"sig"')


if __name__ == "__main__":
    unittest.main()
