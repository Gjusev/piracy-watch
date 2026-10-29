"""Findings store: a single JSONL file that dedupes by finding id.

A finding's identity is the hash of ``(product, source, url)`` — the same
URL seen by two sources is deliberately two findings (different evidence,
different kits). The store is the memory between runs: re-found findings
get their ``last_seen`` bumped, brand-new URLs become ``new`` findings
(which is what triggers alerts and DMCA kit generation). Scale for this
MVP is hundreds of findings, so the file is rewritten atomically on save.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import VALID_STATUSES
from .sources.base import Finding


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path):
        self.path = path
        self._findings: dict[str, Finding] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn last line must not poison the store
            if not isinstance(raw, dict):
                continue
            try:
                finding = Finding.from_dict(raw)
            except (TypeError, ValueError):
                # A hand-edited line that fails validation would otherwise
                # silently delete the finding on the next save — say so.
                print(f"warning: {self.path}: skipping invalid finding line: {line[:80]}", file=sys.stderr)
                continue
            self._findings[finding.finding_id] = finding

    def all(self) -> list[Finding]:
        return sorted(self._findings.values(), key=lambda f: (f.status, f.product, f.location))

    def get(self, finding_id: str) -> Finding | None:
        return self._findings.get(finding_id)

    def upsert(self, finding: Finding) -> str:
        """Merge a scanned finding into the store.

        Returns ``"new"`` if this URL is new, ``"seen"`` if it was already
        known (in which case ``last_seen`` is refreshed and stronger
        evidence — more signatures — is merged in). Status is never reset:
        a repo you already sent a notice for stays ``notified``.
        """
        stamp = now_iso()
        existing = self._findings.get(finding.finding_id)
        if existing is None:
            finding.first_seen = finding.first_seen or stamp
            finding.last_seen = stamp
            self._findings[finding.finding_id] = finding
            return "new"
        existing.last_seen = stamp
        for sig in finding.signatures:
            if sig not in existing.signatures:
                existing.signatures.append(sig)
        return "seen"

    def set_status(self, finding_id: str, status: str) -> bool:
        if status not in VALID_STATUSES:
            raise ValueError(f"invalid status {status!r}, expected one of {VALID_STATUSES}")
        finding = self._findings.get(finding_id)
        if finding is None:
            return False
        finding.status = status
        return True

    def save(self) -> None:
        """Write the store atomically (tmp file + rename)."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lines = [
            json.dumps(f.to_dict(), ensure_ascii=False, sort_keys=True)
            for f in self.all()
        ]
        tmp = self.path.with_suffix(".jsonl.tmp")
        tmp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        os.replace(tmp, self.path)
