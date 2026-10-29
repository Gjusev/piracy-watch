"""GitHub sources: code search for release signatures, repo search for crack repos.

Honest limitations (documented for users, verified in tests):

- Code search only sees *indexed* default branches and requires a token.
  A crack repo whose default branch has no signature strings will not
  surface here; that is what the repo-search source is for.
- Search API budget is 30 requests/minute, so each source caps queries per
  run (``limits.max_queries_per_source``) and stops cleanly when the local
  or remote budget runs out, keeping the findings gathered so far.
"""

from __future__ import annotations

from ..config import Product
from ..fetch import FetchError, GithubClient, RateLimited
from ..signatures import Signature, contains_signature, match_confidence
from .base import Finding


def _is_own_repo(repo_full_name: str, product: Product) -> bool:
    return (repo_full_name or "").strip().casefold() in product.own_repos


def _str(item: dict, key: str) -> str:
    """Read a string field off an untrusted search item."""
    value = item.get(key)
    return value if isinstance(value, str) else ""


class GithubCodeSource:
    """Find code files containing release signatures (installer names, build ids)."""

    name = "github_code"

    def __init__(self, client: GithubClient, max_queries: int = 10, max_findings_per_query: int = 30):
        self.client = client
        self.max_queries = max_queries
        self.max_findings_per_query = max_findings_per_query

    def scan(self, products: list[Product]) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        warnings: list[str] = []
        for product in products:
            searchable = [s for s in product.signatures if s.code_searchable]
            budget = min(self.max_queries, self.client.queries_left())
            for sig in searchable[:budget]:
                query = f'"{sig.value}"'
                try:
                    items = self.client.search_code(query)[: self.max_findings_per_query]
                except RateLimited as exc:
                    warnings.append(f"github_code: {exc}")
                    return findings, warnings
                except FetchError as exc:
                    warnings.append(f"github_code: {exc}")
                    continue
                findings.extend(self._match_items(product, sig, items))
        return findings, warnings

    def _match_items(self, product: Product, sig: Signature, items: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            repo = item.get("repository") if isinstance(item.get("repository"), dict) else {}
            full_name = _str(repo, "full_name")
            url = _str(item, "html_url")
            # An item without a resolvable repo identity is unusable evidence.
            if not url or not full_name or _is_own_repo(full_name, product):
                continue
            findings.append(
                Finding(
                    product=product.name,
                    source=self.name,
                    url=url,
                    location=full_name or "unknown repo",
                    signatures=[sig.value],
                    confidence=match_confidence(sig),
                    kind="code_match",
                    description=_str(item, "path"),
                )
            )
        return findings


class GithubRepoSource:
    """Find repositories named after 'product + crack term' (keygens, cracks, repacks)."""

    name = "github_repos"

    def __init__(
        self,
        client: GithubClient,
        crack_terms: tuple[str, ...],
        max_queries: int = 10,
        max_findings_per_query: int = 30,
    ):
        self.client = client
        self.crack_terms = crack_terms
        self.max_queries = max_queries
        self.max_findings_per_query = max_findings_per_query

    def scan(self, products: list[Product]) -> tuple[list[Finding], list[str]]:
        findings: list[Finding] = []
        warnings: list[str] = []
        for product in products:
            budget = min(self.max_queries, self.client.queries_left())
            for term in self.crack_terms[:budget]:
                query = f"{product.name} {term}"
                try:
                    items = self.client.search_repositories(query)[: self.max_findings_per_query]
                except RateLimited as exc:
                    warnings.append(f"github_repos: {exc}")
                    return findings, warnings
                except FetchError as exc:
                    warnings.append(f"github_repos: {exc}")
                    continue
                findings.extend(self._match_items(product, term, items))
        return findings, warnings

    def _match_items(self, product: Product, term: str, items: list[dict]) -> list[Finding]:
        findings: list[Finding] = []
        name_sig = Signature(value=product.name, type="name", strength="low")
        term_sig = Signature(value=term, type="name", strength="low")
        for item in items:
            if not isinstance(item, dict):
                continue
            full_name = _str(item, "full_name")
            url = _str(item, "html_url")
            if not url or not full_name or _is_own_repo(full_name, product):
                continue
            description = _str(item, "description")
            in_repo_name = contains_signature(full_name, name_sig)
            if not in_repo_name and not contains_signature(description, name_sig):
                continue  # GitHub returned a fuzzy hit; only keep real product mentions
            confidence = "high" if in_repo_name else "medium"
            # Record only what this repo/page verifiably contains — the query
            # was fuzzy, so "product + crack term" may never literally appear.
            signatures = [product.name]
            if contains_signature(full_name, term_sig) or contains_signature(description, term_sig):
                signatures.append(term)
            findings.append(
                Finding(
                    product=product.name,
                    source=self.name,
                    url=url,
                    location=full_name or "unknown repo",
                    signatures=signatures,
                    confidence=confidence,
                    kind="repo_match",
                    description=description,
                )
            )
        return findings
