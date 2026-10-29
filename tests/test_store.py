"""Tests for the findings store (dedupe, status, persistence)."""

import json
import tempfile
import unittest
from pathlib import Path

from piracy_watch.store import Store
from piracy_watch.sources.base import Finding


def make_finding(url="https://github.com/a/b", **overrides) -> Finding:
    defaults = dict(
        product="WidgetPro",
        source="github_repos",
        url=url,
        location="a/b",
        signatures=["WidgetPro crack"],
        confidence="high",
        kind="repo_match",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "findings.jsonl"
        self.store = Store(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_upsert_new_then_seen(self):
        finding = make_finding()
        self.assertEqual(self.store.upsert(finding), "new")
        again = make_finding()
        self.assertEqual(self.store.upsert(again), "seen")
        self.assertEqual(len(self.store.all()), 1)

    def test_rescan_does_not_reset_status(self):
        finding = make_finding()
        self.store.upsert(finding)
        self.store.set_status(finding.finding_id, "notified")
        self.store.upsert(make_finding())  # same URL, second scan
        stored = self.store.get(finding.finding_id)
        self.assertEqual(stored.status, "notified")

    def test_merges_new_signatures(self):
        finding = make_finding()
        self.store.upsert(finding)
        self.store.upsert(make_finding(signatures=["another-sig"]))
        stored = self.store.get(finding.finding_id)
        self.assertEqual(sorted(stored.signatures), ["WidgetPro crack", "another-sig"])

    def test_different_urls_are_different_findings(self):
        self.store.upsert(make_finding(url="https://github.com/a/b"))
        self.store.upsert(make_finding(url="https://github.com/c/d"))
        self.assertEqual(len(self.store.all()), 2)

    def test_set_status_validation(self):
        finding = make_finding()
        self.store.upsert(finding)
        with self.assertRaises(ValueError):
            self.store.set_status(finding.finding_id, "maybe")
        self.assertFalse(self.store.set_status("unknown-id", "new"))
        self.assertTrue(self.store.set_status(finding.finding_id, "resolved"))
        self.assertEqual(self.store.get(finding.finding_id).status, "resolved")

    def test_save_and_reload_roundtrip(self):
        finding = make_finding()
        self.store.upsert(finding)  # stamps first_seen/last_seen
        self.store.set_status(finding.finding_id, "notified")
        stamped = self.store.get(finding.finding_id)
        self.store.save()
        reloaded = Store(self.path)
        stored = reloaded.get(finding.finding_id)
        self.assertEqual(stored.status, "notified")
        self.assertEqual(stored.first_seen, stamped.first_seen)
        self.assertEqual(stored.last_seen, stamped.last_seen)
        self.assertTrue(stored.first_seen)

    def test_save_is_valid_jsonl(self):
        self.store.upsert(make_finding())
        self.store.save()
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIsInstance(json.loads(lines[0]), dict)

    def test_torn_line_is_ignored(self):
        self.path.write_text('{"bogus": true}\n{torn json', encoding="utf-8")
        store = Store(self.path)
        self.assertEqual(store.all(), [])  # nothing loadable, but no crash


if __name__ == "__main__":
    unittest.main()
