"""Configuration loading and validation for Piracy-Watch.

The config lives in ``watch.json`` next to where you run the tool (it is
git-ignored by default because it contains your vendor contact details,
which end up in DMCA notices). Everything in a fetched page or search
result is untrusted; the config is the only trusted input.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from .signatures import Signature, parse_signature

DEFAULT_CRACK_TERMS = (
    "crack",
    "keygen",
    "patch",
    "serial",
    "activation",
    "nulled",
    "torrent",
    "license key",
    "full version",
    "free download",
)

VALID_STATUSES = ("new", "notified", "resolved", "ignored")


@dataclass(frozen=True)
class Vendor:
    """Who is filing takedown notices. All fields land in generated notices."""

    name: str
    email: str
    address: str = ""
    phone: str = ""


@dataclass(frozen=True)
class Product:
    """A watched product and the signatures that identify its releases."""

    name: str
    signatures: tuple[Signature, ...]
    own_repos: tuple[str, ...] = ()  # lowercase 'owner/repo' excluded from results

    @property
    def code_searchable(self) -> bool:
        return any(s.code_searchable for s in self.signatures)


@dataclass(frozen=True)
class Limits:
    """Defensive HTTP limits: external content never gets a blank cheque."""

    max_queries_per_source: int = 10
    request_timeout_s: int = 15
    max_response_bytes: int = 2_000_000
    max_findings_per_query: int = 30


@dataclass(frozen=True)
class Sources:
    github_code: bool = True
    github_repos: bool = True
    crack_terms: tuple[str, ...] = DEFAULT_CRACK_TERMS
    web_pages: tuple[str, ...] = ()

    @property
    def web_pages_enabled(self) -> bool:
        return bool(self.web_pages)


@dataclass(frozen=True)
class Alerting:
    console: bool = True
    webhook_url: str | None = None


@dataclass(frozen=True)
class Config:
    vendor: Vendor
    products: tuple[Product, ...]
    sources: Sources = field(default_factory=Sources)
    limits: Limits = field(default_factory=Limits)
    alerting: Alerting = field(default_factory=Alerting)


def _require_str(raw: dict, key: str, where: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{where}: '{key}' must be a non-empty string")
    return value.strip()


def parse_config(raw: dict) -> Config:
    """Validate a decoded watch.json document into a Config."""
    if not isinstance(raw, dict):
        raise ValueError("config root must be a JSON object")

    vendor_raw = raw.get("vendor")
    if not isinstance(vendor_raw, dict):
        raise ValueError("config: 'vendor' must be an object")
    vendor = Vendor(
        name=_require_str(vendor_raw, "name", "vendor"),
        email=_require_str(vendor_raw, "email", "vendor"),
        address=str(vendor_raw.get("address", "")).strip(),
        phone=str(vendor_raw.get("phone", "")).strip(),
    )

    products_raw = raw.get("products")
    if not isinstance(products_raw, list) or not products_raw:
        raise ValueError("config: 'products' must be a non-empty list")

    products: list[Product] = []
    seen_names: set[str] = set()
    for idx, entry in enumerate(products_raw):
        where = f"products[{idx}]"
        if not isinstance(entry, dict):
            raise ValueError(f"{where}: must be an object")
        name = _require_str(entry, "name", where)
        key = name.casefold()
        if key in seen_names:
            raise ValueError(f"{where}: duplicate product name {name!r}")
        seen_names.add(key)

        sigs_raw = entry.get("signatures")
        if not isinstance(sigs_raw, list) or not sigs_raw:
            raise ValueError(f"{where}: 'signatures' must be a non-empty list")
        signatures = tuple(parse_signature(s) for s in sigs_raw)

        own_raw = entry.get("own_repos", [])
        if not isinstance(own_raw, list):
            raise ValueError(f"{where}: 'own_repos' must be a list of 'owner/repo' strings")
        own = tuple(str(r).strip().casefold() for r in own_raw if str(r).strip())

        products.append(Product(name=name, signatures=signatures, own_repos=own))

    sources_raw = raw.get("sources", {})
    if not isinstance(sources_raw, dict):
        raise ValueError("config: 'sources' must be an object")
    crack_terms = tuple(
        str(t).strip()
        for t in sources_raw.get("crack_terms", DEFAULT_CRACK_TERMS)
        if str(t).strip()
    )
    pages_raw = sources_raw.get("web_pages", [])
    if not isinstance(pages_raw, list):
        raise ValueError("config: sources.web_pages must be a list of URLs")
    web_pages = tuple(_normalize_url(str(u).strip()) for u in pages_raw if str(u).strip())

    limits_raw = raw.get("limits", {})
    if not isinstance(limits_raw, dict):
        raise ValueError("config: 'limits' must be an object")
    limits = Limits(
        max_queries_per_source=int(limits_raw.get("max_queries_per_source", 10)),
        request_timeout_s=int(limits_raw.get("request_timeout_s", 15)),
        max_response_bytes=int(limits_raw.get("max_response_bytes", 2_000_000)),
        max_findings_per_query=int(limits_raw.get("max_findings_per_query", 30)),
    )

    alert_raw = raw.get("alert", {})
    if not isinstance(alert_raw, dict):
        raise ValueError("config: 'alert' must be an object")
    webhook = alert_raw.get("webhook_url")
    alerting = Alerting(
        console=bool(alert_raw.get("console", True)),
        webhook_url=str(webhook).strip() if webhook else None,
    )

    return Config(vendor=vendor, products=tuple(products), sources=Sources(
        github_code=bool(sources_raw.get("github_code", True)),
        github_repos=bool(sources_raw.get("github_repos", True)),
        crack_terms=crack_terms or DEFAULT_CRACK_TERMS,
        web_pages=web_pages,
    ), limits=limits, alerting=alerting)


def _normalize_url(url: str) -> str:
    """Only http(s) URLs are ever fetched."""
    lowered = url.casefold()
    if not (lowered.startswith("https://") or lowered.startswith("http://")):
        raise ValueError(f"web page source must be an http(s) URL, got {url!r}")
    return url


def load_config(path: Path) -> Config:
    """Load and validate a watch.json file."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{path}: invalid JSON: {exc}") from exc
    return parse_config(raw)
