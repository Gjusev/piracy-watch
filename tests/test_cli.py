"""End-to-end CLI tests: scan/store/kit/dashboard wiring with stubbed sources."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from piracy_watch import cli
from piracy_watch.alerts import alert_console, send_webhook
from piracy_watch.config import parse_config
from piracy_watch.sources.base import Finding

CONFIG = parse_config(json.loads(cli.EXAMPLE_CONFIG))


def make_finding(url="https://github.com/cracker/widgetpro-crack") -> Finding:
    return Finding(
        product="WidgetPro",
        source="github_repos",
        url=url,
        location="cracker/widgetpro-crack",
        signatures=["WidgetPro crack"],
        confidence="high",
        kind="repo_match",
    )


class StubSource:
    name = "stub"

    def __init__(self, findings):
        self.findings = findings

    def scan(self, products):
        return list(self.findings), []


class TestAlerts(unittest.TestCase):
    def test_console_alert_format(self):
        alert = alert_console([make_finding()])
        self.assertIn("1 new piracy finding", alert)
        self.assertIn("cracker/widgetpro-crack", alert)
        self.assertIn("HIGH", alert)

    def test_console_alert_empty(self):
        self.assertEqual(alert_console([]), "")

    def test_webhook_failure_is_non_fatal(self):
        delivered, message = send_webhook("http://127.0.0.1:1/nowhere", [make_finding()], timeout_s=1)
        self.assertFalse(delivered)
        self.assertIn("failed", message)


class TestScanCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.config_path = Path(self.tmp.name) / "watch.json"
        self.config_path.write_text(cli.EXAMPLE_CONFIG, encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def _scan(self, findings, extra_args=()):
        argv = [
            "scan",
            "--config", str(self.config_path),
            "--out", str(self.out),
            *extra_args,
        ]
        with patch.object(cli, "build_sources", return_value=[StubSource(findings)]):
            return cli.main(argv)

    def test_dry_run_performs_no_network(self):
        rc = cli.main(["scan", "--config", str(self.config_path), "--dry-run"])
        self.assertEqual(rc, 0)

    def test_first_scan_creates_finding_kit_and_dashboard(self):
        rc = self._scan([make_finding()])
        self.assertEqual(rc, 0)
        store_path = self.out / "findings.jsonl"
        dashboard = self.out / "dashboard.html"
        self.assertTrue(store_path.exists())
        self.assertTrue(dashboard.exists())
        self.assertIn("widgetpro-crack", dashboard.read_text(encoding="utf-8"))
        kit_root = self.out / "dmca" / "widgetpro"
        kits = list(kit_root.iterdir())
        self.assertEqual(len(kits), 1)
        self.assertTrue((kits[0] / "github-dmca-notice.md").exists())

    def test_rescan_does_not_duplicate_or_realert(self):
        self._scan([make_finding()])
        # Second scan sees the same URL: no new findings, still one kit dir.
        rc = self._scan([make_finding()])
        self.assertEqual(rc, 0)
        self.assertEqual(len(list((self.out / "dmca" / "widgetpro").iterdir())), 1)
        lines = (self.out / "findings.jsonl").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)

    def test_fail_on_new_exits_one(self):
        rc = self._scan([make_finding()], extra_args=["--fail-on-new"])
        self.assertEqual(rc, 1)

    def test_fail_on_new_false_when_nothing_new(self):
        self._scan([make_finding()])
        rc = self._scan([make_finding()], extra_args=["--fail-on-new"])
        self.assertEqual(rc, 0)

    def test_source_failure_does_not_break_scan(self):
        class ExplodingSource:
            name = "boom"

            def scan(self, products):
                raise RuntimeError("kaboom")

        with patch.object(cli, "build_sources", return_value=[ExplodingSource(), StubSource([make_finding()])]):
            rc = cli.main(["scan", "--config", str(self.config_path), "--out", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "findings.jsonl").exists())


class TestStatusAndKitCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.out = Path(self.tmp.name) / "out"
        self.config_path = Path(self.tmp.name) / "watch.json"
        self.config_path.write_text(cli.EXAMPLE_CONFIG, encoding="utf-8")
        with patch.object(cli, "build_sources", return_value=[StubSource([make_finding()])]):
            cli.main(["scan", "--config", str(self.config_path), "--out", str(self.out)])
        store = cli.Store(self.out / "findings.jsonl")
        self.finding_id = store.all()[0].finding_id

    def tearDown(self):
        self.tmp.cleanup()

    def test_status_updates_finding(self):
        rc = cli.main(["status", self.finding_id, "notified", "--out", str(self.out)])
        self.assertEqual(rc, 0)
        store = cli.Store(self.out / "findings.jsonl")
        self.assertEqual(store.get(self.finding_id).status, "notified")
        self.assertIn("notified", (self.out / "dashboard.html").read_text(encoding="utf-8"))

    def test_status_unknown_id_fails(self):
        rc = cli.main(["status", "nope", "resolved", "--out", str(self.out)])
        self.assertEqual(rc, 1)

    def test_kit_regenerates_for_stored_finding(self):
        rc = cli.main(["kit", self.finding_id, "--config", str(self.config_path), "--out", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "dmca" / "widgetpro" / self.finding_id / "evidence.json").exists())

    def test_report_rebuilds_dashboard(self):
        (self.out / "dashboard.html").unlink()
        rc = cli.main(["report", "--out", str(self.out)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.out / "dashboard.html").exists())


class TestInitCommand(unittest.TestCase):
    def test_init_writes_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "watch.json"
            rc = cli.main(["init", "--config", str(target)])
            self.assertEqual(rc, 0)
            config = json.loads(target.read_text(encoding="utf-8"))
            self.assertIn("vendor", config)
            self.assertIn("products", config)

    def test_init_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "watch.json"
            cli.main(["init", "--config", str(target)])
            rc = cli.main(["init", "--config", str(target)])
            self.assertEqual(rc, 1)
            rc = cli.main(["init", "--config", str(target), "--force"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
