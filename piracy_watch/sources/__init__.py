"""Scan sources and the scanner that runs them."""

from __future__ import annotations

from ..config import Config
from ..fetch import Fetcher, GithubClient
from .base import Finding, Source
from .github import GithubCodeSource, GithubRepoSource
from .web_page import WebPageSource


def build_sources(config: Config, github_token: str | None = None) -> list[Source]:
    """Instantiate every enabled source from the config."""
    fetcher = Fetcher(
        timeout_s=config.limits.request_timeout_s,
        max_bytes=config.limits.max_response_bytes,
    )
    client = GithubClient(fetcher, token=github_token)
    sources: list[Source] = []
    if config.sources.github_code and config.products and any(p.code_searchable for p in config.products):
        sources.append(
            GithubCodeSource(
                client,
                max_queries=config.limits.max_queries_per_source,
                max_findings_per_query=config.limits.max_findings_per_query,
            )
        )
    if config.sources.github_repos and config.products:
        sources.append(
            GithubRepoSource(
                client,
                crack_terms=config.sources.crack_terms,
                max_queries=config.limits.max_queries_per_source,
                max_findings_per_query=config.limits.max_findings_per_query,
            )
        )
    if config.sources.web_pages_enabled:
        sources.append(WebPageSource("pages", config.sources.web_pages, fetcher))
    return sources


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that point at the same URL (same finding id).

    The same file can surface under two signature queries; merging keeps one
    finding with the union of signatures and the strongest confidence.
    """
    rank = {"high": 2, "medium": 1, "low": 0}
    by_id: dict[str, Finding] = {}
    order: list[str] = []
    for finding in findings:
        existing = by_id.get(finding.finding_id)
        if existing is None:
            by_id[finding.finding_id] = finding
            order.append(finding.finding_id)
            continue
        for sig in finding.signatures:
            if sig not in existing.signatures:
                existing.signatures.append(sig)
        if rank[finding.confidence] > rank[existing.confidence]:
            existing.confidence = finding.confidence
        if finding.first_seen and (not existing.first_seen or finding.first_seen < existing.first_seen):
            existing.first_seen = finding.first_seen
    return [by_id[i] for i in order]


def run_sources(sources: list[Source], config: Config) -> tuple[list[Finding], list[str]]:
    """Run every source once, returning merged findings and warnings."""
    findings: list[Finding] = []
    warnings: list[str] = []
    for source in sources:
        try:
            source_findings, source_warnings = source.scan(list(config.products))
        except Exception as exc:  # a source must never take the whole scan down
            warnings.append(f"{source.name}: unexpected failure: {exc.__class__.__name__}: {exc}")
            continue
        findings.extend(source_findings)
        warnings.extend(source_warnings)
    return merge_findings(findings), warnings


__all__ = [
    "Finding",
    "Source",
    "GithubCodeSource",
    "GithubRepoSource",
    "WebPageSource",
    "build_sources",
    "merge_findings",
    "run_sources",
]
