"""Static HTML dashboard: "where is your software cracked".

Single self-contained file, no JavaScript, no server. Every string that
originates from outside the process (URLs, repo names, signatures, page
titles) is HTML-escaped in both element and attribute context, and links
are only emitted for http(s) URLs — search results are untrusted and
must not be able to inject markup.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from .sources.base import Finding

STATUS_STYLES = {
    "new": ("#b42318", "#fef3f2", "new"),
    "notified": ("#b54708", "#fffaeb", "notified"),
    "resolved": ("#067647", "#ecfdf3", "resolved"),
    "ignored": ("#475467", "#f2f4f7", "ignored"),
}


def safe_href(url: str) -> str:
    """Scheme gate: return the URL if it is a safe http(s) link, else '#'.

    This only filters the scheme — the *caller* must still escape the
    returned string for its context (``_esc(..., quote=True)`` for href
    attributes). A http(s) URL can still contain ``"``, ``<`` or ``>``,
    which would break out of an unescaped attribute.
    """
    lowered = (url or "").strip().casefold()
    if lowered.startswith("https://") or lowered.startswith("http://"):
        return url.strip()
    return "#"


def _esc(value: str) -> str:
    return html.escape(value or "", quote=True)


def render_html(findings: list[Finding], generated_at: str | None = None) -> str:
    """Render the full dashboard page for the given findings."""
    now = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = Counter(f.status for f in findings)
    by_product: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda f: (f.product.casefold(), f.confidence, f.location.casefold())):
        # Group case-insensitively so "WidgetPro" and "widgetpro" land together.
        by_product.setdefault(f.product.casefold(), []).append(f)

    rows: list[str] = []
    for _, items in by_product.items():
        rows.append(
            f'<tr class="product-row"><td colspan="7">{_esc(items[0].product)} '
            f'<span class="count">{len(items)}</span></td></tr>'
        )
        for f in items:
            color, bg, label = STATUS_STYLES.get(f.status, STATUS_STYLES["ignored"])
            badge = (
                f'<span class="badge" style="color:{color};background:{bg};'
                f'border:1px solid {color}22">{label}</span>'
            )
            kit = f"{f.product.casefold().replace(' ', '-')}/{f.finding_id}"
            rows.append(
                "<tr>"
                f"<td>{badge}</td>"
                f'<td><span class="conf conf-{_esc(f.confidence)}">{_esc(f.confidence)}</span></td>'
                f'<td>{_esc(f.source)}</td>'
                f'<td><a href="{_esc(safe_href(f.url))}" rel="noreferrer noopener">{_esc(f.location)}</a>'
                f'<div class="sig">{_esc(", ".join(f.signatures[:4]))}</div></td>'
                f"<td>{_esc(f.first_seen[:10])}</td>"
                f"<td>{_esc(f.last_seen[:10])}</td>"
                f'<td><code class="kit">dmca/{_esc(kit)}/</code></td>'
                "</tr>"
            )

    body = "\n".join(rows) or '<tr><td colspan="7" class="empty">No findings yet — run a scan.</td></tr>'
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Piracy-Watch — where is your software cracked</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         margin: 0; background: #fcfcfd; color: #101828; }}
  header {{ padding: 28px 32px 12px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  .sub {{ color: #475467; margin: 0; }}
  .summary {{ padding: 8px 32px 20px; display: flex; gap: 10px; flex-wrap: wrap; }}
  .pill {{ border: 1px solid #d0d5dd; border-radius: 999px; padding: 3px 12px;
           background: #fff; font-size: 13px; }}
  table {{ border-collapse: collapse; width: calc(100% - 64px); margin: 0 32px 40px;
           background: #fff; border: 1px solid #eaecf0; border-radius: 10px;
           overflow: hidden; }}
  th {{ text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .04em;
        color: #475467; background: #f9fafb; padding: 10px 14px;
        border-bottom: 1px solid #eaecf0; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #f2f4f7; vertical-align: top; }}
  tr.product-row td {{ background: #f9fafb; font-weight: 600; font-size: 14px; }}
  .count {{ background: #eef4ff; color: #175cd3; border-radius: 999px;
            padding: 1px 9px; margin-left: 8px; font-size: 12px; }}
  a {{ color: #175cd3; }}
  .sig {{ color: #667085; font-size: 12px; margin-top: 2px; }}
  .badge {{ border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 600; }}
  .conf {{ font-size: 12px; border-radius: 6px; padding: 1px 8px; }}
  .conf-high {{ background: #fef3f2; color: #b42318; }}
  .conf-medium {{ background: #fffaeb; color: #b54708; }}
  .conf-low {{ background: #f2f4f7; color: #475467; }}
  .kit {{ font-size: 11px; color: #475467; }}
  code.kit {{ white-space: nowrap; }}
  td.empty {{ color: #475467; text-align: center; padding: 32px; }}
  footer {{ color: #667085; font-size: 12px; padding: 0 32px 40px; }}
</style>
</head>
<body>
<header>
  <h1>Piracy-Watch</h1>
  <p class="sub">Where your software is cracked — generated {html.escape(now)}.
     Kits in <code>out/dmca/&lt;product&gt;/&lt;finding&gt;/</code>; verify before sending.</p>
</header>
<div class="summary">
  <span class="pill">total {len(findings)}</span>
  <span class="pill">new {counts.get("new", 0)}</span>
  <span class="pill">notified {counts.get("notified", 0)}</span>
  <span class="pill">resolved {counts.get("resolved", 0)}</span>
  <span class="pill">ignored {counts.get("ignored", 0)}</span>
</div>
<table>
<thead><tr>
<th>Status</th><th>Confidence</th><th>Source</th><th>Location &amp; matched signatures</th>
<th>First seen</th><th>Last seen</th><th>DMCA kit</th>
</tr></thead>
<tbody>
{body}
</tbody>
</table>
<footer>
Detection is automated evidence, not proof — review every lead before sending a
DMCA notice. Notices are drafted, never auto-sent.
</footer>
</body>
</html>
"""


def write_dashboard(findings: list[Finding], out_path: Path) -> Path:
    """Write the dashboard, returning the path."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(findings), encoding="utf-8")
    return out_path
