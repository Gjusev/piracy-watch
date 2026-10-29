"""Source interface and the Finding record.

A source turns (config, client) into findings. Sources must tolerate
hostile payloads: they only read whitelisted keys off decoded JSON, and
any string that ends up in a finding is data, never code.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Protocol

from ..config import Product
from ..signatures import finding_id

VALID_STATUSES = ("new", "notified", "resolved", "ignored")
VALID_CONFIDENCE = ("high", "medium", "low")


@dataclass
class Finding:
    """One place where a release signature surfaced."""

    product: str
    source: str  # 'github_code' | 'github_repos' | 'web_page:<name>'
    url: str
    location: str  # repo 'owner/name' or page title/URL
    signatures: list[str]
    confidence: str
    kind: str  # 'code_match' | 'repo_match' | 'page_match'
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    status: str = "new"
    finding_id: str = field(default="")

    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = finding_id(self.product, self.source, self.url)
        if not self.first_seen:
            self.first_seen = self.last_seen or ""
        if self.status not in VALID_STATUSES:
            raise ValueError(f"invalid finding status {self.status!r}")
        if self.confidence not in VALID_CONFIDENCE:
            raise ValueError(f"invalid finding confidence {self.confidence!r}")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Finding":
        known = {k: raw[k] for k in cls.__dataclass_fields__ if k in raw}
        return cls(**known)


class Source(Protocol):
    """A scan source: name + one run over the config, returning findings."""

    name: str

    def scan(self, products: list[Product]) -> tuple[list[Finding], list[str]]:
        """Return (findings, warnings). Warnings carry recoverable errors."""
        ...
