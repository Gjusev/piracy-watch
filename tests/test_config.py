"""Tests for config parsing/validation."""

import json
import tempfile
import unittest
from pathlib import Path

from piracy_watch.cli import EXAMPLE_CONFIG
from piracy_watch.config import load_config, parse_config


class TestParseConfig(unittest.TestCase):
    def setUp(self):
        self.config = parse_config(json.loads(EXAMPLE_CONFIG))

    def test_valid_example_config(self):
        self.assertEqual(self.config.vendor.name, "ACME GmbH")
        self.assertEqual(len(self.config.products), 1)
        product = self.config.products[0]
        self.assertEqual(product.name, "WidgetPro")
        self.assertEqual(len(product.signatures), 3)
        self.assertTrue(product.code_searchable)
        self.assertIn("acme/widgetpro", product.own_repos)

    def test_defaults(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw.pop("limits")
        raw.pop("alert")
        config = parse_config(raw)
        self.assertEqual(config.limits.max_queries_per_source, 10)
        self.assertTrue(config.alerting.console)
        self.assertIsNone(config.alerting.webhook_url)
        self.assertTrue(config.sources.github_code)
        self.assertEqual(len(config.sources.crack_terms), 10)

    def test_vendor_required(self):
        raw = json.loads(EXAMPLE_CONFIG)
        del raw["vendor"]
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_vendor_fields_required(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["vendor"]["email"] = "  "
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_products_must_be_non_empty(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["products"] = []
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_duplicate_product_names_rejected(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["products"].append(raw["products"][0])
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_product_needs_signatures(self):
        raw = json.loads(EXAMPLE_CONFIG)
        del raw["products"][0]["signatures"]
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_bad_signature_rejected(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["products"][0]["signatures"][0]["strength"] = "wild"
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_web_pages_must_be_http(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["sources"]["web_pages"] = ["ftp://example.net/board"]
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_web_pages_accepted(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["sources"]["web_pages"] = ["https://forum.example.net/board/13"]
        config = parse_config(raw)
        self.assertTrue(config.sources.web_pages_enabled)
        self.assertEqual(config.sources.web_pages, ("https://forum.example.net/board/13",))

    def test_own_repos_are_casefolded(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["products"][0]["own_repos"] = [" ACME/WidgetPro "]
        config = parse_config(raw)
        self.assertEqual(config.products[0].own_repos, ("acme/widgetpro",))

    def test_load_config_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watch.json"
            path.write_text(EXAMPLE_CONFIG, encoding="utf-8")
            config = load_config(path)
            self.assertEqual(config.vendor.email, "legal@acme.example")

    def test_load_config_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "watch.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(path)

    def test_webhook_url_must_be_http(self):
        raw = json.loads(EXAMPLE_CONFIG)
        raw["alert"]["webhook_url"] = "ftp://hooks.example.net/x"
        with self.assertRaises(ValueError):
            parse_config(raw)

    def test_https_webhook_accepted_without_warning(self):
        import warnings as warnings_mod

        raw = json.loads(EXAMPLE_CONFIG)
        raw["alert"]["webhook_url"] = "https://hooks.example.net/x"
        with warnings_mod.catch_warnings():
            warnings_mod.simplefilter("error")  # any warning fails the test
            config = parse_config(raw)
        self.assertEqual(config.alerting.webhook_url, "https://hooks.example.net/x")

    def test_http_webhook_warns(self):
        import warnings as warnings_mod

        raw = json.loads(EXAMPLE_CONFIG)
        raw["alert"]["webhook_url"] = "http://hooks.example.net/x"
        with warnings_mod.catch_warnings(record=True) as caught:
            warnings_mod.simplefilter("always")
            config = parse_config(raw)
        self.assertTrue(any("unencrypted" in str(w.message) for w in caught))

    def test_http_web_page_warns(self):
        import warnings as warnings_mod

        raw = json.loads(EXAMPLE_CONFIG)
        raw["sources"]["web_pages"] = ["http://board.example.net/t/13"]
        with warnings_mod.catch_warnings(record=True) as caught:
            warnings_mod.simplefilter("always")
            config = parse_config(raw)
        self.assertEqual(config.sources.web_pages, ("http://board.example.net/t/13",))
        self.assertTrue(any("prefer https" in str(w.message) for w in caught))


if __name__ == "__main__":
    unittest.main()
