"""Tests for the GitHub and web-page sources (transport stubbed)."""

import unittest

from piracy_watch.config import Product
from piracy_watch.sources.base import Finding
from piracy_watch.fetch import FetchError, GithubClient, RateLimited
from piracy_watch.signatures import Signature
from piracy_watch.sources.github import GithubCodeSource, GithubRepoSource
from piracy_watch.sources.web_page import WebPageSource


def make_product() -> Product:
    return Product(
        name="WidgetPro",
        signatures=(
            Signature(value="widgetpro-setup-2.1.0.exe", type="binary_name", strength="high"),
            Signature(value="WidgetPro", type="name", strength="low"),
        ),
        own_repos=("acme/widgetpro",),
    )


class StubClient(GithubClient):
    """GithubClient with a preloaded response list, no transport.

    If ``error`` is set it is raised once all queued responses are used.
    """

    def __init__(self, responses=None, error=None):
        self.responses = list(responses or [])
        self.error = error
        self.queries_used = 0
        self.queries: list[str] = []

    def _pop(self):
        if self.responses:
            return self.responses.pop(0)
        if self.error is not None:
            raise self.error
        return []

    def search_code(self, query, per_page=30):
        self.queries_used += 1
        self.queries.append(query)
        return self._pop()

    def search_repositories(self, query, per_page=30):
        self.queries_used += 1
        self.queries.append(query)
        return self._pop()


class TestGithubCodeSource(unittest.TestCase):
    def test_matches_become_findings(self):
        items = [
            {
                "html_url": "https://github.com/cracker/repo/blob/main/setup.txt",
                "path": "setup.txt",
                "repository": {"full_name": "cracker/repo"},
            }
        ]
        source = GithubCodeSource(StubClient([items]))
        findings, warnings = source.scan([make_product()])
        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.kind, "code_match")
        self.assertEqual(finding.confidence, "high")
        self.assertEqual(finding.location, "cracker/repo")
        self.assertEqual(finding.signatures, ["widgetpro-setup-2.1.0.exe"])
        self.assertIn('"widgetpro-setup-2.1.0.exe"', source.client.queries[0])
        # The weak product name is never sent to code search.
        self.assertEqual(len(source.client.queries), 1)

    def test_own_repos_excluded(self):
        items = [
            {
                "html_url": "https://github.com/acme/widgetpro/blob/main/README.md",
                "repository": {"full_name": "ACME/WidgetPro"},
            }
        ]
        source = GithubCodeSource(StubClient([items]))
        findings, _ = source.scan([make_product()])
        self.assertEqual(findings, [])

    def test_untrusted_items_skipped(self):
        items = ["string-item", None, 42, {"html_url": "", "repository": {}}]
        source = GithubCodeSource(StubClient([items]))
        findings, warnings = source.scan([make_product()])
        self.assertEqual(findings, [])

    def test_rate_limited_keeps_partial_findings(self):
        # Two searchable signatures: the first query succeeds, the second hits
        # the rate limit — the findings gathered so far must survive.
        items = [
            {
                "html_url": "https://github.com/a/b/blob/main/x",
                "repository": {"full_name": "a/b"},
            }
        ]
        product = Product(
            name="WidgetPro",
            signatures=(
                Signature(value="widgetpro-setup-2.1.0.exe", type="binary_name", strength="high"),
                Signature(value="WP-BUILD-internal", type="build_string", strength="high"),
            ),
        )
        source = GithubCodeSource(StubClient([items], error=RateLimited("limited")))
        findings, warnings = source.scan([product])
        self.assertEqual(len(findings), 1)  # from the first signature's query
        self.assertEqual(len(warnings), 1)
        self.assertTrue(warnings[0].startswith("github_code:"))
        self.assertIn("limited", warnings[0].casefold())

    def test_fetch_error_recorded_as_warning(self):
        source = GithubCodeSource(StubClient(error=FetchError("boom")))
        findings, warnings = source.scan([make_product()])
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)


class TestGithubRepoSource(unittest.TestCase):
    def test_crack_repo_named_after_product(self):
        items = [
            {
                "full_name": "cracker/widgetpro-crack",
                "html_url": "https://github.com/cracker/widgetpro-crack",
                "description": "WidgetPro full version free",
            }
        ]
        source = GithubRepoSource(StubClient([items]), crack_terms=("crack",))
        findings, warnings = source.scan([make_product()])
        self.assertEqual(warnings, [])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "high")  # product name in repo name
        self.assertIn("WidgetPro crack", findings[0].signatures)

    def test_description_only_match_is_medium(self):
        items = [
            {
                "full_name": "cracker/unrelated-name",
                "html_url": "https://github.com/cracker/unrelated-name",
                "description": "crack for widgetpro",
            }
        ]
        source = GithubRepoSource(StubClient([items]), crack_terms=("crack",))
        findings, _ = source.scan([make_product()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "medium")

    def test_no_product_mention_dropped(self):
        items = [
            {
                "full_name": "cracker/other-tool-crack",
                "html_url": "https://github.com/cracker/other-tool-crack",
                "description": "crack for something else entirely",
            }
        ]
        source = GithubRepoSource(StubClient([items]), crack_terms=("crack",))
        findings, _ = source.scan([make_product()])
        self.assertEqual(findings, [])

    def test_untrusted_items_skipped(self):
        source = GithubRepoSource(StubClient([["nope", {"no_url": True}]]), crack_terms=("crack",))
        findings, _ = source.scan([make_product()])
        self.assertEqual(findings, [])


class TestMergeFindings(unittest.TestCase):
    def _finding(self, url="https://github.com/a/b", signatures=("WidgetPro crack",), confidence="high"):
        return Finding(
            product="WidgetPro",
            source="github_repos",
            url=url,
            location="a/b",
            signatures=list(signatures),
            confidence=confidence,
            kind="repo_match",
        )

    def test_same_url_findings_are_merged(self):
        from piracy_watch.sources import merge_findings

        a = self._finding()
        b = self._finding(signatures=("extra-sig",), confidence="low")
        merged = merge_findings([a, b])
        self.assertEqual(len(merged), 1)
        self.assertEqual(sorted(merged[0].signatures), ["WidgetPro crack", "extra-sig"])
        self.assertEqual(merged[0].confidence, "high")  # strongest wins

    def test_different_urls_survive(self):
        from piracy_watch.sources import merge_findings

        merged = merge_findings([self._finding(), self._finding(url="https://github.com/c/d")])
        self.assertEqual(len(merged), 2)


class StubFetcher:
    def __init__(self, responses=None, error=None):
        self.responses = list(responses or [])
        self.error = error

    def get_text(self, url, headers=None):
        if self.error is not None:
            raise self.error
        if not self.responses:
            return 200, ""
        return self.responses.pop(0)


class TestWebPageSource(unittest.TestCase):
    def test_signature_in_page_matches(self):
        fetcher = StubFetcher([(200, "Post: anyone got widgetpro-setup-2.1.0.exe working?")])
        source = WebPageSource("pages", ("https://board.example.net/t/13",), fetcher)
        findings, warnings = source.scan([make_product()])
        self.assertEqual(warnings, [])
        # One finding for the page, listing every signature that matched.
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "page_match")
        self.assertEqual(findings[0].location, "board.example.net")
        self.assertEqual(findings[0].confidence, "high")
        self.assertEqual(
            sorted(findings[0].signatures),
            ["WidgetPro", "widgetpro-setup-2.1.0.exe"],
        )

    def test_product_name_requires_word_boundary(self):
        fetcher = StubFetcher([(200, "widgetproject is a different thing")])
        source = WebPageSource("pages", ("https://board.example.net/t/1",), fetcher)
        findings, _ = source.scan([make_product()])
        self.assertEqual(findings, [])

    def test_product_name_alone_is_low_confidence(self):
        fetcher = StubFetcher([(200, "WidgetPro leaked everywhere!!!")])
        source = WebPageSource("pages", ("https://board.example.net/t/2",), fetcher)
        findings, _ = source.scan([make_product()])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].confidence, "low")

    def test_non_200_is_warning(self):
        fetcher = StubFetcher([(404, "")])
        source = WebPageSource("pages", ("https://board.example.net/gone",), fetcher)
        findings, warnings = source.scan([make_product()])
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)

    def test_transport_error_is_warning(self):
        fetcher = StubFetcher(error=FetchError("timeout"))
        source = WebPageSource("pages", ("https://board.example.net/slow",), fetcher)
        findings, warnings = source.scan([make_product()])
        self.assertEqual(findings, [])
        self.assertEqual(len(warnings), 1)


if __name__ == "__main__":
    unittest.main()
