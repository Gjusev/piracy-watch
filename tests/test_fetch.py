"""Tests for the fetcher and the GitHub client (all transport is stubbed)."""

import unittest

from piracy_watch.fetch import FetchError, Fetcher, GithubClient, RateLimited


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


if __name__ == "__main__":
    unittest.main()
