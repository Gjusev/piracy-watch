"""Tests for signature definitions and matching."""

import unittest

from piracy_watch.signatures import (
    Signature,
    contains_signature,
    finding_id,
    match_confidence,
    parse_signature,
)


class TestSignatureValidation(unittest.TestCase):
    def test_valid_signature(self):
        sig = Signature(value="app-1.2.exe", type="binary_name", strength="high")
        self.assertTrue(sig.code_searchable)

    def test_empty_value_rejected(self):
        with self.assertRaises(ValueError):
            Signature(value="  ", type="binary_name", strength="high")

    def test_bad_type_rejected(self):
        with self.assertRaises(ValueError):
            Signature(value="x", type="hash", strength="high")

    def test_bad_strength_rejected(self):
        with self.assertRaises(ValueError):
            Signature(value="x", type="name", strength="extreme")

    def test_low_strength_not_code_searchable(self):
        sig = Signature(value="WidgetPro", type="name", strength="low")
        self.assertFalse(sig.code_searchable)

    def test_parse_defaults_to_medium(self):
        sig = parse_signature({"value": "x", "type": "build_string"})
        self.assertEqual(sig.strength, "medium")

    def test_parse_requires_value(self):
        with self.assertRaises(ValueError):
            parse_signature({"type": "name"})


class TestContainsSignature(unittest.TestCase):
    def test_substring_match_casefolded(self):
        sig = Signature(value="WidgetPro-Setup.exe", type="binary_name", strength="high")
        self.assertTrue(contains_signature("Download WIDGETPRO-setup.EXE here", sig))

    def test_low_strength_respects_word_boundaries(self):
        sig = Signature(value="widgetpro", type="name", strength="low")
        self.assertTrue(contains_signature("Get WidgetPro free", sig))
        self.assertTrue(contains_signature("widgetpro!", sig))
        self.assertFalse(contains_signature("widgetproject", sig))
        self.assertFalse(contains_signature("mywidgetpro2", sig))

    def test_high_strength_matches_inside_words(self):
        sig = Signature(value="wpbuild", type="build_string", strength="high")
        self.assertTrue(contains_signature("x_wpbuild_y", sig))

    def test_empty_haystack_is_no_match(self):
        sig = Signature(value="x", type="build_string", strength="high")
        self.assertFalse(contains_signature("", sig))


class TestConfidenceAndIds(unittest.TestCase):
    def test_strong_signature_keeps_confidence(self):
        sig = Signature(value="x", type="binary_name", strength="high")
        self.assertEqual(match_confidence(sig), "high")

    def test_low_is_capped_at_low(self):
        sig = Signature(value="x", type="name", strength="low")
        self.assertEqual(match_confidence(sig), "low")
        self.assertEqual(match_confidence(sig, in_name=False), "low")

    def test_medium_outside_name_degrades(self):
        sig = Signature(value="x", type="build_string", strength="medium")
        self.assertEqual(match_confidence(sig, in_name=False), "low")

    def test_finding_id_is_stable_and_differs_by_url(self):
        a = finding_id("WidgetPro", "github_code", "https://github.com/a/b/blob/1")
        b = finding_id("WidgetPro", "github_code", "https://github.com/a/b/blob/1")
        c = finding_id("WidgetPro", "github_code", "https://github.com/a/b/blob/2")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(len(a), 16)


if __name__ == "__main__":
    unittest.main()
