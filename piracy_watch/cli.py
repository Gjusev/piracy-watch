"""Command-line interface: init, scan, watch, report, kit, status."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import __version__
from .alerts import alert_console, send_webhook
from .config import load_config
from .dashboard import write_dashboard
from .dmca import generate_kit, kit_dir
from .fetch import GithubClient
from .sources import build_sources, run_sources
from .sources.github import GithubCodeSource, GithubRepoSource
from .store import Store

WATCH_CONFIG = "watch.json"
FINDINGS_FILE = "findings.jsonl"
DEFAULT_INTERVAL_S = 6 * 3600


def _resolve(config_arg: str | None) -> Path:
    return Path(config_arg or os.environ.get("PIRACY_WATCH_CONFIG") or WATCH_CONFIG)


def _github_token() -> str | None:
    """Token from the environment only — never argv (visible in `ps`)."""
    for name in ("PIRACY_WATCH_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"):
        value = os.environ.get(name)
        if value:
            return value
    return None


def cmd_init(args: argparse.Namespace) -> int:
    """Write a starter watch.json and exit."""
    target = Path(args.config or WATCH_CONFIG)
    if target.exists() and not args.force:
        print(f"{target} already exists (use --force to overwrite)")
        return 1
    target.write_text(EXAMPLE_CONFIG, encoding="utf-8")
    print(f"Wrote starter config to {target}")
    print("Next: replace the vendor details, add your products' signatures, then:")
    print("  piracy-watch scan --dry-run    # see the queries without network access")
    print("  piracy-watch scan              # first scan (GITHUB_TOKEN recommended)")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Run every enabled source once, store/alert/kit/dashboard."""
    config_path = _resolve(args.config)
    config = load_config(config_path)
    out_dir = Path(args.out)

    if args.dry_run:
        print("Dry run — the following queries would be executed:")
        shown = 0
        if config.sources.github_code:
            for product in config.products:
                for sig in product.signatures:
                    if sig.code_searchable:
                        print(f"  code  search: \"{sig.value}\"  ({product.name})")
                        shown += 1
        if config.sources.github_repos:
            for product in config.products:
                for term in config.sources.crack_terms:
                    print(f"  repo  search: {product.name} {term}  ({product.name})")
                    shown += 1
        # Pages are fetched once per scan, not once per product.
        if config.sources.web_pages_enabled:
            for url in config.sources.web_pages:
                print(f"  page  fetch:  {url}")
                shown += 1
        print(f"{shown} operations total. No network access was performed.")
        return 0

    store = Store(out_dir / FINDINGS_FILE)
    sources = build_sources(config, github_token=_github_token())
    client = next(
        (s.client for s in sources if isinstance(s, (GithubCodeSource, GithubRepoSource))),
        None,
    )
    findings, warnings = run_sources(sources, config)
    for warning in warnings:
        print(f"warning: {warning}", file=sys.stderr)

    new_findings = []
    for finding in findings:
        if store.upsert(finding) == "new":
            # Re-read the stored copy (status/first_seen may be enriched there).
            stored = store.get(finding.finding_id)
            new_findings.append(stored or finding)

    kits = []
    for finding in new_findings:
        kits.append(generate_kit(config, finding, out_dir))

    store.save()
    dashboard_path = write_dashboard(store.all(), out_dir / "dashboard.html")

    if config.alerting.console and new_findings:
        print(alert_console(new_findings))
    if config.alerting.webhook_url and new_findings:
        delivered, message = send_webhook(config.alerting.webhook_url, new_findings)
        print(message)

    queries = f"{client.queries_used} GitHub queries used" if client else "no GitHub source enabled"
    print(
        f"Scan complete: {len(findings)} hit(s), {len(new_findings)} new, "
        f"{len(kits)} DMCA kit(s) drafted. Dashboard: {dashboard_path} ({queries})"
    )
    if args.fail_on_new and new_findings:
        print(f"--fail-on-new: {len(new_findings)} new finding(s)", file=sys.stderr)
        return 1
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    """Loop scan on an interval; Ctrl-C exits cleanly (cron-friendly).

    A crashed scan (bad config, failed kit write, anything unexpected) is
    reported and the loop keeps running — a daemon must survive its own
    failures. Only Ctrl-C stops it.
    """
    interval = args.interval
    print(f"Watching every {interval // 3600}h{(interval % 3600) // 60}m — Ctrl-C to stop")
    try:
        while True:
            try:
                rc = cmd_scan(args)
                if rc != 0:
                    print(f"scan exited with {rc}; continuing watch", file=sys.stderr)
            except KeyboardInterrupt:
                raise
            except Exception as exc:  # noqa: BLE001 — the watch loop outlives any single scan
                print(f"scan crashed: {exc.__class__.__name__}: {exc}; continuing watch", file=sys.stderr)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nWatch stopped.")
        return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Regenerate the dashboard from the store, without scanning."""
    store = Store(Path(args.out) / FINDINGS_FILE)
    path = write_dashboard(store.all(), Path(args.out) / "dashboard.html")
    print(f"Dashboard for {len(store.all())} finding(s): {path}")
    return 0


def cmd_kit(args: argparse.Namespace) -> int:
    """(Re)generate the DMCA kit for one stored finding."""
    config = load_config(_resolve(args.config))
    store = Store(Path(args.out) / FINDINGS_FILE)
    finding = store.get(args.finding_id)
    if finding is None:
        print(f"Unknown finding id: {args.finding_id}", file=sys.stderr)
        return 1
    path = generate_kit(config, finding, Path(args.out))
    print(f"DMCA kit: {path}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Update a finding's status and refresh the dashboard."""
    store = Store(Path(args.out) / FINDINGS_FILE)
    if not store.set_status(args.finding_id, args.status):
        print(f"Unknown finding id: {args.finding_id}", file=sys.stderr)
        return 1
    store.save()
    path = write_dashboard(store.all(), Path(args.out) / "dashboard.html")
    print(f"{args.finding_id} -> {args.status}; dashboard refreshed: {path}")
    return 0


EXAMPLE_CONFIG = """{
  "vendor": {
    "name": "ACME GmbH",
    "email": "legal@acme.example",
    "address": "Musterstrasse 1, 10115 Berlin, Germany",
    "phone": "+49 30 000000"
  },
  "products": [
    {
      "name": "WidgetPro",
      "own_repos": ["acme/widgetpro"],
      "signatures": [
        { "value": "widgetpro-setup-2.1.0.exe", "type": "binary_name", "strength": "high" },
        { "value": "WP-BUILD-2026-x9f2-internal", "type": "build_string", "strength": "high" },
        { "value": "WidgetPro", "type": "name", "strength": "low" }
      ]
    }
  ],
  "sources": {
    "github_code": true,
    "github_repos": true,
    "crack_terms": ["crack", "keygen", "patch", "serial", "activation", "nulled", "torrent", "license key", "full version", "free download"],
    "web_pages": []
  },
  "alert": { "console": true, "webhook_url": null },
  "limits": {
    "max_queries_per_source": 10,
    "request_timeout_s": 15,
    "max_response_bytes": 2000000,
    "max_findings_per_query": 30
  }
}
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="piracy-watch",
        description="Watch public code hosts for release signatures of your software, "
        "and generate ready-to-review DMCA takedown kits.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="write a starter watch.json")
    p_init.add_argument("--config", default=None, help="config path (default ./watch.json)")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing config")
    p_init.set_defaults(func=cmd_init)

    p_scan = sub.add_parser("scan", help="run all enabled sources once")
    p_scan.add_argument("--config", default=None, help="config path (default ./watch.json)")
    p_scan.add_argument("--out", default="out", help="output directory (default ./out)")
    p_scan.add_argument("--dry-run", action="store_true", help="print queries, no network access")
    p_scan.add_argument("--fail-on-new", action="store_true", help="exit 1 when new findings appear")
    p_scan.set_defaults(func=cmd_scan)

    p_watch = sub.add_parser("watch", help="scan on an interval (daemon)")
    p_watch.add_argument("--config", default=None)
    p_watch.add_argument("--out", default="out")
    p_watch.add_argument("--interval", type=int, default=DEFAULT_INTERVAL_S, help="seconds between scans")
    p_watch.set_defaults(func=cmd_watch)

    p_report = sub.add_parser("report", help="regenerate the dashboard from stored findings")
    p_report.add_argument("--out", default="out")
    p_report.set_defaults(func=cmd_report)

    p_kit = sub.add_parser("kit", help="generate the DMCA kit for a finding")
    p_kit.add_argument("finding_id")
    p_kit.add_argument("--config", default=None)
    p_kit.add_argument("--out", default="out")
    p_kit.set_defaults(func=cmd_kit)

    p_status = sub.add_parser("status", help="update a finding's status")
    p_status.add_argument("finding_id")
    p_status.add_argument("status", choices=("new", "notified", "resolved", "ignored"))
    p_status.add_argument("--out", default="out")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
