"""HTTP fetcher with defensive limits and the GitHub API client.

Everything fetched from the outside world is untrusted data. The fetcher
enforces: http(s) schemes only, a per-socket timeout plus a total fetch
deadline, and a response size cap. Redirects are only followed to the
same host over http(s) — never to other hosts, never downgraded to plain
http, never to other schemes — so an Authorization header can never leak
to a redirect target. Bodies are decoded lossily — a broken or hostile
payload must never crash the scan. The GitHub API client additionally
refuses any non-https URL.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from . import __version__

USER_AGENT = f"piracy-watch/{__version__} (+https://github.com/Gjusev/piracy-watch)"


class FetchError(RuntimeError):
    """A fetch failed in a way the scan should report but survive."""


class RateLimited(FetchError):
    """GitHub rate limit exhausted; the scan should stop this source."""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Redirect policy: same-host http(s) only.

    urllib's default redirect handler copies *all* headers — including
    ``Authorization`` — onto the redirected request and follows https→http
    downgrades silently. This handler refuses every redirect that changes
    host, downgrades the scheme, or leaves http(s), so a token really only
    ever reaches the host it was set for. Refused redirects surface as an
    HTTPError, which :meth:`Fetcher.get` returns as a normal (status, body)
    result so callers can report the hop and move on.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        origin = urllib.parse.urlsplit(req.full_url)
        parts = urllib.parse.urlsplit(newurl)
        scheme = (parts.scheme or origin.scheme).casefold()  # relative Location keeps the origin scheme
        if scheme not in ("http", "https"):
            raise urllib.error.HTTPError(
                newurl, code, f"{msg} - refusing redirect to non-http(s) URL {newurl!r}", headers, fp
            )
        if origin.scheme.casefold() == "https" and scheme == "http":
            raise urllib.error.HTTPError(
                newurl, code, f"{msg} - refusing https→http redirect to {newurl!r}", headers, fp
            )
        if (parts.netloc or origin.netloc).casefold() != origin.netloc.casefold():
            raise urllib.error.HTTPError(
                newurl, code, f"{msg} - refusing cross-host redirect to {newurl!r}", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Fetcher:
    """Minimal HTTP GET client with timeouts and size caps.

    ``timeout_s`` bounds each socket operation; ``total_timeout_s`` bounds
    the whole response (headers + body), defaulting to twice ``timeout_s``,
    so a slow-drip server cannot stall a scan indefinitely.
    """

    def __init__(
        self,
        timeout_s: int = 15,
        max_bytes: int = 2_000_000,
        total_timeout_s: int | None = None,
    ):
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.total_timeout_s = total_timeout_s if total_timeout_s is not None else max(timeout_s, 1) * 2
        self._opener = urllib.request.build_opener(_SafeRedirectHandler())

    def get(self, url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        """GET *url*, returning (status, body) capped at ``max_bytes``.

        HTTP error statuses (4xx/5xx) and refused redirects (3xx) are
        returned as-is so callers can decide policy (rate limits, skips).
        Transport failures raise :class:`FetchError`.
        """
        scheme = urllib.parse.urlsplit(url).scheme.casefold()
        if scheme not in ("http", "https"):
            raise FetchError(f"refusing to fetch non-http URL: {url!r}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with self._opener.open(request, timeout=self.timeout_s) as response:
                return response.status, self._read_capped(response)
        except urllib.error.HTTPError as exc:
            return exc.code, self._read_capped(exc)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            raise FetchError(f"fetch failed for {url!r}: {exc}") from exc

    def get_json(self, url: str, headers: dict[str, str] | None = None) -> tuple[int, object]:
        """GET and decode a JSON body; invalid JSON raises FetchError."""
        status, body = self.get(url, headers)
        try:
            return status, json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise FetchError(f"invalid JSON from {url!r}: {exc}") from exc

    def get_text(self, url: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
        """GET and decode a body as (lossily decoded) text."""
        status, body = self.get(url, headers)
        return status, body.decode("utf-8", errors="replace")

    def _read_capped(self, stream) -> bytes:
        deadline = time.monotonic() + self.total_timeout_s
        chunks: list[bytes] = []
        total = 0
        # read1 returns whatever the peer has already sent instead of
        # blocking until a full 64 KiB buffer arrives, so the deadline
        # below is actually checked between chunks of a slow-drip body.
        reader = getattr(stream, "read1", None) or stream.read
        while True:
            if time.monotonic() >= deadline:
                break  # total deadline: a slow-drip body must not stall the scan
            chunk = reader(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                break  # truncate: an oversized response still yields usable data
            chunks.append(chunk)
        return b"".join(chunks)


class GithubClient:
    """GitHub REST client for the two search endpoints Piracy-Watch uses.

    The token never leaves this process except in the Authorization header
    to api.github.com — enforced here (https-only API URLs) and by the
    fetcher's redirect policy (no cross-host or downgraded redirects).
    Search API budget is 30 requests/minute authenticated (10
    unauthenticated), so every source caps its query count.
    """

    API = "https://api.github.com"

    def __init__(
        self,
        fetcher: Fetcher,
        token: str | None = None,
        sleeper=time.sleep,
        max_rate_limit_wait_s: int = 60,
    ):
        self.fetcher = fetcher
        self.token = (token or "").strip() or None
        self._sleep = sleeper
        self.max_rate_limit_wait_s = max_rate_limit_wait_s
        self.queries_used = 0

    def _headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _search(self, path: str, params: dict[str, str]) -> dict:
        if self.queries_used >= 30:
            raise RateLimited("local query budget exhausted (30 searches per run)")
        url = f"{self.API}{path}"
        if urllib.parse.urlsplit(url).scheme.casefold() != "https":
            raise FetchError(f"refusing to send the token over a non-https API URL: {url!r}")
        query = urllib.parse.urlencode(params)
        self.queries_used += 1
        for attempt in (1, 2):  # one retry on transient GitHub 5xx
            status, payload = self.fetcher.get_json(f"{url}?{query}", self._headers())
            if status == 200:
                if not isinstance(payload, dict):
                    raise FetchError(f"unexpected search payload type from {path}")
                return payload
            if status in (403, 429):
                self._handle_rate_limit(path)
                continue
            if status >= 500 and attempt == 1:
                self._sleep(1.0)
                continue
            raise FetchError(f"GitHub search {path} returned HTTP {status}")
        raise FetchError(f"GitHub search {path} failed after retry")

    def _handle_rate_limit(self, path: str) -> None:
        """Wait out a rate limit if it clears soon, otherwise give up."""
        status, payload = self.fetcher.get_json(f"{self.API}/rate_limit", self._headers())
        reset_s = None
        if status == 200 and isinstance(payload, dict):
            search = payload.get("resources", {}).get("search", {})
            reset_s = max(0, int(search.get("reset", 0)) - int(time.time()) + 1)
        if reset_s is not None and reset_s <= self.max_rate_limit_wait_s:
            self._sleep(reset_s)
            return
        raise RateLimited(f"GitHub search rate limited at {path} (resets in {reset_s}s)")

    def queries_left(self) -> int:
        """Remaining local search budget (GitHub allows 30 searches/minute)."""
        return max(0, 30 - self.queries_used)

    def search_code(self, query: str, per_page: int = 30) -> list[dict]:
        """Code search: returns item dicts (html_url, repository, path, ...)."""
        payload = self._search("/search/code", {"q": query, "per_page": str(per_page)})
        items = payload.get("items", [])
        return items if isinstance(items, list) else []

    def search_repositories(self, query: str, per_page: int = 30) -> list[dict]:
        """Repo search: returns item dicts (full_name, html_url, description)."""
        payload = self._search("/search/repositories", {"q": query, "per_page": str(per_page)})
        items = payload.get("items", [])
        return items if isinstance(items, list) else []
