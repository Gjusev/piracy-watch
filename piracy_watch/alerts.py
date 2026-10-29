"""Alerting: console output and an optional generic webhook.

The webhook POSTs a small JSON summary of new findings to a URL of your
choice (Slack-compatible endpoints work out of the box). Alert delivery
failures are reported, never raised — a dead webhook must not kill a scan.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from . import __version__
from .fetch import USER_AGENT
from .sources.base import Finding


def alert_console(findings: list[Finding]) -> str:
    """Render the console alert block (also returned for tests/logs)."""
    if not findings:
        return ""
    lines = [f"⚠️  {len(findings)} new piracy finding(s):"]
    for f in findings:
        lines.append(f"  [{f.confidence.upper():6}] {f.product} — {f.location}")
        lines.append(f"          {f.url}")
        lines.append(f"          matched: {', '.join(f.signatures[:3])}")
    return "\n".join(lines)


def send_webhook(url: str, findings: list[Finding], timeout_s: int = 10) -> tuple[bool, str]:
    """POST new findings as JSON to *url*. Returns (delivered, message)."""
    payload = {
        "tool": "piracy-watch",
        "version": __version__,
        "new_findings": [f.to_dict() for f in findings],
        "count": len(findings),
    }
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return True, f"webhook delivered (HTTP {response.status})"
    except urllib.error.HTTPError as exc:
        # Non-2xx statuses surface as HTTPError from urlopen.
        return False, f"webhook returned HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 — any delivery failure is non-fatal
        return False, f"webhook delivery failed: {exc.__class__.__name__}: {exc}"
