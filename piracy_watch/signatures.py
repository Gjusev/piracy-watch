"""Release signatures and the matching rules that turn them into findings.

A signature is a string that only appears in *your* releases: an installer
file name, a unique build id baked into the binary, or (weakest) the product
name itself. Strength decides how each source uses it and what confidence a
match gets:

- ``high``   — binary names and build strings; sent to GitHub code search,
               substring-matched in web pages.
- ``medium`` — e.g. an internal resource name; treated like ``high``.
- ``low``    — the bare product name; never sent to code search (far too
               noisy), only word-boundary matched in web pages and repo
               descriptions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

STRENGTHS = ("high", "medium", "low")
TYPES = ("binary_name", "build_string", "name")

#: Signature strengths that are specific enough for GitHub code search.
CODE_SEARCH_STRENGTHS = ("high", "medium")


@dataclass(frozen=True)
class Signature:
    """One watchable fingerprint of a release."""

    value: str
    type: str
    strength: str

    def __post_init__(self) -> None:
        if not self.value or not self.value.strip():
            raise ValueError("signature value must be a non-empty string")
        if self.type not in TYPES:
            raise ValueError(f"signature type must be one of {TYPES}, got {self.type!r}")
        if self.strength not in STRENGTHS:
            raise ValueError(f"signature strength must be one of {STRENGTHS}, got {self.strength!r}")

    @property
    def code_searchable(self) -> bool:
        """Whether this signature is specific enough for GitHub code search."""
        return self.strength in CODE_SEARCH_STRENGTHS


def parse_signature(raw: dict) -> Signature:
    """Build a Signature from a config entry, defaulting to medium strength."""
    if not isinstance(raw, dict) or "value" not in raw:
        raise ValueError(f"signature entry must be an object with 'value', got {raw!r}")
    return Signature(
        value=str(raw["value"]).strip(),
        type=str(raw.get("type", "binary_name")),
        strength=str(raw.get("strength", "medium")),
    )


def contains_signature(haystack: str, sig: Signature) -> bool:
    """Return whether *haystack* (untrusted text) contains the signature.

    Strong signatures match as a plain casefolded substring. The bare product
    name (``low``) only matches on word boundaries so "WidgetPro" does not
    match "widgetproject". Nothing from the haystack is ever executed.
    """
    folded = (haystack or "").casefold()
    needle = sig.value.casefold()
    if not folded or not needle:
        return False
    if sig.strength == "low":
        pattern = r"(?<![a-z0-9])" + re.escape(needle) + r"(?![a-z0-9])"
        return re.search(pattern, folded) is not None
    return needle in folded


def match_confidence(sig: Signature, in_name: bool = True) -> str:
    """Confidence for a text match, optionally degraded for weak placements.

    A ``low``-strength product name found anywhere is at best a ``low``
    confidence lead; strong signatures keep their strength as confidence.
    """
    if sig.strength == "low":
        return "low"
    if not in_name and sig.strength == "medium":
        return "low"
    return sig.strength


def finding_id(product: str, source: str, url: str) -> str:
    """Stable identity of a finding: hash of (product, source, url).

    The same URL under two sources is two findings on purpose — each
    carries its own evidence and kit.
    """
    import hashlib

    key = f"{product}|{source}|{url}".encode("utf-8", errors="replace")
    return hashlib.sha256(key).hexdigest()[:16]
