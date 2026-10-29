# Piracy-Watch

**Know where your software is cracked.** Piracy-Watch watches public code
hosts for *signatures of your releases* — installer file names, unique build
strings — finds repos and pages distributing cracks or keygens, and drafts a
complete DMCA takedown kit for every hit, ready for you to review and send.

Built after ["GitHub refuses to remove cracked copies of my software"
(HN, 586 pt / 349 c)](https://news.ycombinator.com/item?id=49982498): indie
vendors have no tooling to even *find* their cracked software, let alone
file takedowns. Piracy-Watch is that tooling.

```
⚠️  3 new piracy finding(s):
  [HIGH  ] WidgetPro — cracker/widgetpro-crack
          https://github.com/cracker/widgetpro-crack
          matched: WidgetPro crack

Scan complete: 12 hit(s), 3 new, 3 DMCA kit(s) drafted. Dashboard: out/dashboard.html (12 GitHub queries used)
```

## How it works

1. **Signatures.** You list fingerprints that only appear in *your*
   releases: an installer name (`widgetpro-setup-2.1.0.exe`), a build id
   baked into the binary, or (weakest) the product name.
2. **Sources.** Each scan run queries:
   - **GitHub code search** for your installer names / build strings —
     catches repack repos and crack repos that include your artifacts.
   - **GitHub repository search** for `yourproduct + crack|keygen|patch|…`
     — catches keygen repos even when the code never mentions your builds.
   - **Web pages** you point it at (forum boards, index pages) — the
     torrent scene has no stable API, so you configure the pages your
     audience actually uses.
3. **Findings store.** Every hit is deduped by URL in `findings.jsonl`;
   re-found URLs update `last_seen`, new URLs become alerts.
4. **DMCA kits.** For every new finding, a kit is generated:
   - `README.md` — a human checklist: verify the hit *actually infringes*
     before doing anything (a matched string alone can be a bug report),
     archive evidence, then send.
   - `github-dmca-notice.md` — a takedown notice containing **all seven
     elements** GitHub's DMCA policy requires, pre-filled with your
     vendor data and the infringing URLs. Fields the tool cannot know are
     marked `[FILL IN]`.
   - `host-abuse-email.txt` — the equivalent for non-GitHub hosts.
   - `evidence.json` — machine-readable detection record.
5. **Dashboard.** A static, zero-JS `dashboard.html` showing where your
   software is cracked: per product, status (`new` → `notified` →
   `resolved`/`ignored`), confidence, matched signatures, DMCA kit path.

**Piracy-Watch never sends anything.** DMCA notices are signed under
penalty of perjury; automated evidence is a lead, not proof. A human
verifies and sends. The tool's job is to make that take minutes instead
of never happening.

## Quickstart

Requires Python 3.10+ (standard library only, no dependencies to install).

```console
$ python -m piracy_watch init          # writes ./watch.json
$ # edit watch.json: your vendor details + your products' signatures
$ export GITHUB_TOKEN=ghp_…            # recommended (see limitations)
$ python -m piracy_watch scan --dry-run    # show queries, no network
$ python -m piracy_watch scan          # first scan
$ python -m piracy_watch report        # re-render out/dashboard.html
```

Keep watching (6 h default; or just run `scan` from cron):

```console
$ python -m piracy_watch watch --interval 21600
```

When you have verified a hit and sent the notice:

```console
$ python -m piracy_watch status <finding-id> notified
```

### Configuration (`watch.json`)

```jsonc
{
  "vendor": {                       // who files the notices
    "name": "ACME GmbH",
    "email": "legal@acme.example",
    "address": "Musterstrasse 1, 10115 Berlin, Germany",
    "phone": "+49 30 000000"
  },
  "products": [
    {
      "name": "WidgetPro",
      "own_repos": ["acme/widgetpro"],           // excluded from results
      "signatures": [
        // strength "high"/"medium" go to code search
        { "value": "widgetpro-setup-2.1.0.exe", "type": "binary_name", "strength": "high" },
        // baked into the binary: strongest signal you can have
        { "value": "WP-BUILD-2026-x9f2-internal", "type": "build_string", "strength": "high" },
        // bare name: word-boundary matched only, never code-searched
        { "value": "WidgetPro", "type": "name", "strength": "low" }
      ]
    }
  ],
  "sources": {
    "github_code": true,
    "github_repos": true,
    "crack_terms": ["crack", "keygen", "patch", "serial", "activation", "nulled", "torrent", "license key", "full version", "free download"],
    "web_pages": ["https://forum.example.net/board/13"]   // optional
  },
  "alert": { "console": true, "webhook_url": null },            // Slack-compatible webhook
  "limits": { "max_queries_per_source": 10 }                     // API budget guard
}
```

**Which build strings?** Anything your installer or binary embeds that a
legitimate third party would never contain: internal build ids, unique
resource names, EULA checksums. Put one in a file, run
`grep -r <string>`, and check that only your releases hit.

## Honest limitations

- **GitHub code search needs a token** (`GITHUB_TOKEN`) and only indexes
  *default branches* of repos above a minimum size. Cracks in releases,
  tags, or dormant forks are invisible to it — that is why repository
  search is on by default.
- **Search API budget is 30 queries/minute** (10 unauthenticated).
  Piracy-Watch caps queries per run (`limits.max_queries_per_source`) and
  stops a source cleanly when the budget runs out, keeping findings
  gathered so far. With many products, split scans across runs.
- **No torrent tracker API.** The web-page source is deliberately generic:
  point it at public pages and let the MOK interviews decide which sources
  matter. Scraping private trackers is out of scope.
- **Detection ≠ infringement.** Expect false positives (support threads,
  compatibility shims, memes). The kit checklist exists for exactly this;
  do not send notices for non-infringing content.
- **DMCA is a process, not a switch.** GitHub may ask you to refile or
  argue. Record what you sent (`status notified`), keep evidence, and
  consult a lawyer for serious damage or counter-notices. This tool is
  not legal advice.

## Security posture

- Every fetch runs with a hard timeout and response size cap; oversized
  or hostile responses truncate instead of crashing the scan.
- Fetched content is *data only*: dashboard output is HTML-escaped, links
  are restricted to http(s), nothing fetched is ever executed.
- Your GitHub token is read from the environment and sent only to
  `api.github.com`; it is never logged or stored.
- `watch.json` (which contains your contact details) and `out/` are
  git-ignored by default.

## Development

```console
$ python -m unittest discover -s tests -v    # 96 tests, no dependencies
```

The test suite stubs all transport — no network access is needed.
`scan --dry-run` is safe to run anywhere for the same reason.

## Roadmap (S1/F3 candidates)

- More sources: package registries (PyPI/npm typosquatting of your name),
  archive.org software collections, key HN threads.
- Similarity matching on release artifacts (fuzzy installer names).
- Per-product alert routing and weekly digest email.
- Optional GitHub issue filing on infringing repos.

## License

MIT — see [LICENSE](LICENSE).
