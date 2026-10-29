"""Tests for the dashboard renderer — especially untrusted-content escaping."""

import unittest

from piracy_watch.dashboard import render_html, safe_href, write_dashboard
from piracy_watch.sources.base import Finding


def make_finding(url="https://github.com/cracker/widgetpro-crack", **overrides) -> Finding:
    defaults = dict(
        product="WidgetPro",
        source="github_repos",
        url=url,
        location="cracker/widgetpro-crack",
        signatures=["WidgetPro crack"],
        confidence="high",
        kind="repo_match",
        first_seen="2026-10-29T10:00:00+00:00",
        last_seen="2026-10-29T10:00:00+00:00",
    )
    defaults.update(overrides)
    return Finding(**defaults)


class TestUntrustedContent(unittest.TestCase):
    """Search results are attacker-controlled; the dashboard must neutralize them."""

    def test_script_in_location_is_escaped(self):
        html = render_html([make_finding(location="<script>alert(1)</script>")])
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_script_in_signature_is_escaped(self):
        html = render_html([make_finding(signatures=['<img src=x onerror="alert(1)">'])])
        self.assertNotIn("<img src=x", html)
        self.assertIn("&lt;img", html)

    def test_javascript_url_neutralized(self):
        html = render_html([make_finding(url="javascript:alert(document.cookie)")])
        self.assertNotIn("javascript:alert", html)
        self.assertIn('href="#"', html)

    def test_product_name_is_escaped(self):
        html = render_html([make_finding(product="Widget</td>Pro")])
        self.assertNotIn("Widget</td>Pro", html)
        self.assertIn("Widget&lt;/td&gt;Pro", html)

    def test_https_links_survive(self):
        html = render_html([make_finding()])
        self.assertIn('href="https://github.com/cracker/widgetpro-crack"', html)

    # --- attribute-context payloads (MOK-46 F1): the href value itself is
    # attacker-controlled and must be escaped at the sink, not just gated. ---

    def test_url_with_quote_breakout_is_escaped(self):
        url = 'https://evil.example/x"><script>alert(document.domain)</script>'
        html = render_html([make_finding(url=url)])
        self.assertNotIn("<script>alert(document.domain)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        # The attribute never breaks out: no raw double quote from the payload.
        self.assertNotIn('"><script', html)

    def test_url_with_event_handler_is_escaped(self):
        url = 'https://evil.example/x" onmouseover="fetch(\'https://att.example\')"'
        html = render_html([make_finding(url=url)])
        # The raw quote-delimited event handler never appears — the payload
        # stays inside the quoted href attribute as inert escaped text.
        self.assertNotIn('" onmouseover="', html)
        self.assertIn("&quot;", html)

    def test_url_with_control_chars_stays_inside_attribute(self):
        url = "https://ok.example/a\r\nSet-Cookie: pwned=1"
        html = render_html([make_finding(url=url)])
        # Control chars cannot break out of the quoted attribute: the payload
        # is followed by nothing but the closing quote and the rel attribute.
        self.assertIn('\r\nSet-Cookie: pwned=1" rel="noreferrer noopener">', html)

    def test_safe_href_is_scheme_gate_only(self):
        # safe_href deliberately passes quote-bearing http(s) URLs through —
        # escaping is the sink's job (see the tests above).
        self.assertEqual(
            safe_href('https://evil.example/x"><script>'),
            'https://evil.example/x"><script>',
        )
        self.assertEqual(safe_href("https://ok.example/a"), "https://ok.example/a")


class TestDashboardRendering(unittest.TestCase):
    def test_summary_counts_all_statuses(self):
        findings = [
            make_finding(),
            make_finding(url="https://x.example/1", status="notified"),
            make_finding(url="https://x.example/2", status="resolved"),
            make_finding(url="https://x.example/3", status="ignored"),
        ]
        html = render_html(findings)
        self.assertIn("total 4", html)
        self.assertIn("new 1", html)
        self.assertIn("notified 1", html)
        self.assertIn("resolved 1", html)
        self.assertIn("ignored 1", html)

    def test_empty_state(self):
        html = render_html([])
        self.assertIn("No findings yet", html)

    def test_products_are_grouped(self):
        findings = [
            make_finding(product="Alpha"),
            make_finding(product="alpha"),  # same product name, different case
            make_finding(product="Beta"),
        ]
        html = render_html(findings)
        alpha_section = html.count('<span class="count">')
        self.assertEqual(alpha_section, 2)  # one row per product group

    def test_safe_href(self):
        self.assertEqual(safe_href("https://ok.example/a"), "https://ok.example/a")
        self.assertEqual(safe_href("http://ok.example/a"), "http://ok.example/a")
        self.assertEqual(safe_href("javascript:x"), "#")
        self.assertEqual(safe_href("data:text/html,x"), "#")
        self.assertEqual(safe_href(""), "#")

    def test_write_dashboard_creates_file(self):
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "dashboard.html"
            result = write_dashboard([make_finding()], path)
            self.assertEqual(result, path)
            content = path.read_text(encoding="utf-8")
            self.assertIn("<!doctype html>", content)
            self.assertIn("widgetpro-crack", content)


if __name__ == "__main__":
    unittest.main()
