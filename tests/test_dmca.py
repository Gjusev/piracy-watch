"""Tests for DMCA kit generation (all required notice elements present)."""

import json
import tempfile
import unittest
from pathlib import Path

from piracy_watch.cli import EXAMPLE_CONFIG
from piracy_watch.config import parse_config
from piracy_watch.dmca import generate_kit, kit_dir, render_github_notice, render_host_email
from piracy_watch.sources.base import Finding

CONFIG = parse_config(json.loads(EXAMPLE_CONFIG))

# Elements GitHub's DMCA takedown policy requires in every notice.
REQUIRED_ELEMENTS = (
    "good faith belief",
    "penalty of perjury",
    "authorized to act",
    "dmca@github.com",
    "Contact information",
    "copyrighted work",
    "Signature",
)


def make_finding(url="https://github.com/cracker/widgetpro-crack") -> Finding:
    return Finding(
        product="WidgetPro",
        source="github_repos",
        url=url,
        location="cracker/widgetpro-crack",
        signatures=["WidgetPro crack"],
        confidence="high",
        kind="repo_match",
        description="full version free",
        first_seen="2026-10-29T10:00:00+00:00",
        last_seen="2026-10-29T10:00:00+00:00",
    )


class TestGitHubNotice(unittest.TestCase):
    def setUp(self):
        self.notice = render_github_notice(CONFIG, make_finding())

    def test_all_required_elements_present(self):
        lowered = self.notice.casefold()
        for element in REQUIRED_ELEMENTS:
            self.assertIn(element.casefold(), lowered, f"missing required element: {element}")

    def test_finding_details_included(self):
        self.assertIn("https://github.com/cracker/widgetpro-crack", self.notice)
        self.assertIn("cracker/widgetpro-crack", self.notice)
        self.assertIn("WidgetPro crack", self.notice)

    def test_vendor_contact_included(self):
        self.assertIn("legal@acme.example", self.notice)
        self.assertIn("ACME GmbH", self.notice)

    def test_unknown_fields_left_for_human(self):
        self.assertIn("[FILL IN", self.notice)  # must not invent facts


class TestHostEmail(unittest.TestCase):
    def test_host_email_contains_essentials(self):
        email = render_host_email(CONFIG, make_finding())
        self.assertIn("DMCA", email)
        self.assertIn("https://github.com/cracker/widgetpro-crack", email)
        self.assertIn("abuse@[host-of-url]", email)
        self.assertIn("[FILL IN", email)


class TestKitGeneration(unittest.TestCase):
    def test_kit_contains_all_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            finding = make_finding()
            path = generate_kit(CONFIG, finding, out_dir)
            expected = kit_dir(out_dir, finding)
            self.assertEqual(path, expected)
            self.assertTrue((path / "README.md").exists())
            self.assertTrue((path / "github-dmca-notice.md").exists())
            self.assertTrue((path / "host-abuse-email.txt").exists())
            self.assertTrue((path / "evidence.json").exists())

    def test_checklist_instructs_manual_review_and_status_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding = make_finding()
            path = generate_kit(CONFIG, finding, Path(tmp))
            checklist = (path / "README.md").read_text(encoding="utf-8")
            self.assertIn("Verify the infringement manually", checklist)
            self.assertIn(f"piracy-watch status {finding.finding_id} notified", checklist)
            self.assertIn("not legal advice", checklist)

    def test_evidence_json_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            finding = make_finding()
            path = generate_kit(CONFIG, finding, Path(tmp))
            evidence = json.loads((path / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(evidence["url"], finding.url)
            self.assertEqual(evidence["finding_id"], finding.finding_id)
            self.assertEqual(evidence["vendor"]["email"], "legal@acme.example")

    def test_kit_path_is_per_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            path_a = generate_kit(CONFIG, make_finding(), out_dir)
            path_b = generate_kit(CONFIG, make_finding(url="https://example.net/other"), out_dir)
            self.assertNotEqual(path_a, path_b)


if __name__ == "__main__":
    unittest.main()
