"""Generic web-page source for pages you point it at.

The S1 spike finding: there is no stable, keyless API for "popular
torrent trackers". Rather than scraping any specific site, this source
checks a user-configured list of public pages (forum boards, index pages,
release blogs — whatever the product audience actually uses, which is
exactly what the MOK-40 interviews should pin down). Each configured URL
is fetched, and every release signature is matched against the page text.

Untrusted-content rules: the page body is only ever searched as text, is
capped in size by the Fetcher, and titles/URLs that end up in findings are
escaped everywhere they are rendered (dashboard) — never executed.
"""

from __future__ import annotations

import urllib.parse

from ..config import Product
from ..fetch import FetchError, Fetcher
from ..signatures import contains_signature, match_confidence
from .base import Finding


def _host(url: str) -> str:
    host = urllib.parse.urlsplit(url).netloc
    return host or "unknown host"


class WebPageSource:
    """Match release signatures in the text of configured public pages."""

    def __init__(self, name: str, urls: tuple[str, ...], fetcher: Fetcher):
        self.name = f"web_page:{name}"
        self.urls = urls
        self.fetcher = fetcher

    def scan(self, products: list[Product]) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        warnings: list[str] = []
        for url in self.urls:
            try:
                status, text = self.fetcher.get_text(url)
            except FetchError as exc:
                warnings.append(f"{self.name}: {exc}")
                continue
            if status != 200:
                warnings.append(f"{self.name}: HTTP {status} for {url}")
                continue
            for product in products:
                findings.extend(self._match_text(product, url, text))
        return findings, warnings

    def _match_text(self, product: Product, url: str, text: str) -> list[Finding]:
        # One finding per (product, URL) listing every signature that hit —
        # several signatures usually match the same crack post.
        matched = [sig for sig in product.signatures if contains_signature(text, sig)]
        if not matched:
            return []
        confidence = max(
            (match_confidence(sig) for sig in matched),
            key=lambda c: {"high": 2, "medium": 1, "low": 0}[c],
        )
        return [
            Finding(
                product=product.name,
                source=self.name,
                url=url,
                location=_host(url),
                signatures=[sig.value for sig in matched],
                confidence=confidence,
                kind="page_match",
                description=f"signature(s) found in page text ({len(text)} chars fetched)",
            )
        ]
