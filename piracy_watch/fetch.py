"""HTTP fetcher with defensive limits and the GitHub API client.

Everything fetched from the outside world is untrusted data. The fetcher
enforces: https-only (except explicitly allowed localhost test URLs in
tests), a hard request timeout, a response size cap, and no following of
redirects into non-http schemes. Bodies are decoded lossily — a broken or
hostile payload must never crash the scan.
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


class Fetcher:
    """Minimal HTTP GET client with timeout and size caps."""

    def __init__(self, timeout_s: int = 15, max_bytes: int = 2_000_000):
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes

    def get(self, url: str, headers: dict[str, str] | None = None) -> tuple[int, bytes]:
        """GET *url*, returning (status, body) capped at ``max_bytes``.

        HTTP error statuses (4xx/5xx) are returned as-is so callers can
        decide policy (rate limits, skips). Transport failures raise
        :class:`FetchError`.
        """
        scheme = urllib.parse.urlsplit(url).scheme.casefold()
        if scheme not in ("http", "https"):
            raise FetchError(f"refusing to fetch non-http URL: {url!r}")
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
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
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = stream.read(65536)
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
    to api.github.com. Search API budget is 30 requests/minute authenticated
    (10 unauthenticated), so every source caps its query count.
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
        query = urllib.parse.urlencode(params)
        self.queries_used += 1
        for attempt in (1, 2):  # one retry on transient GitHub 5xx
            status, payload = self.fetcher.get_json(f"{self.API}{path}?{query}", self._headers())
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
