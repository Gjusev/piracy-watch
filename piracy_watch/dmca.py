"""DMCA kit generation: ready-to-review takedown packages, never auto-sent.

A matched URL is *evidence of a lead*, not proof of infringement — a repo
containing one string can be a bug report or a compatibility shim. That is
why a kit always contains a human checklist first, and why this tool has
no "send" button: DMCA notices are signed under penalty of perjury, so a
human must verify the infringement and send the notice themselves.

The GitHub notice template includes every element required by GitHub's
DMCA takedown policy (docs.github.com/en/site-policy/content-removal-policies/dmca-takedown-policy):
signature, work identification, infringing material + URLs, contact info,
good-faith statement, accuracy-under-perjury statement, and authorization
statement. Elements the tool cannot know are marked ``[FILL IN]``.
"""

from __future__ import annotations

import json
from pathlib import Path

from .config import Config
from .sources.base import Finding


def kit_dir(out_dir: Path, finding: Finding) -> Path:
    slug = finding.product.casefold().replace(" ", "-") or "product"
    return out_dir / "dmca" / slug / finding.finding_id


def _blockquote_finding(finding: Finding) -> str:
    lines = [f"- **Product:** {finding.product}", f"- **Source:** {finding.source}"]
    lines.append(f"- **URL:** {finding.url}")
    lines.append(f"- **Location:** {finding.location}")
    lines.append(f"- **Matched signatures:** {', '.join(finding.signatures)}")
    lines.append(f"- **Confidence:** {finding.confidence}")
    if finding.description:
        lines.append(f"- **Detail:** {finding.description}")
    return "\n".join(lines)


def render_github_notice(config: Config, finding: Finding) -> str:
    """Full GitHub DMCA takedown notice with required elements filled in."""
    v = config.vendor
    return f"""To: dmca@github.com
Subject: DMCA Takedown Notice — {finding.product}

Dear GitHub,

I am the copyright owner, or an agent authorized to act on behalf of the
copyright owner, of the work described below. I am submitting this notice
pursuant to Section 512(c) of the DMCA (17 U.S.C. § 512(c)) and GitHub's
DMCA Takedown Policy.

## 1. Identification of the copyrighted work

[FILL IN: describe the copyrighted work, e.g. "{finding.product}, a commercial
software product distributed by {v.name}; copyright registered as [FILL IN if
applicable]". Attach or link evidence of ownership where available.]

## 2. Identification of the infringing material and its location

The following repository/content distributes or facilitates cracking of the
copyrighted work without authorization:

{_blockquote_finding(finding)}

Specific infringing URL(s):
- {finding.url}

## 3. Contact information

- **Complainant:** {v.name}
- **Email:** {v.email}
- **Address:** {v.address or "[FILL IN: postal address]"}
- **Phone:** {v.phone or "[FILL IN: phone number]"}

## 4. Good faith statement

I have a good faith belief that the use of the material described above is
not authorized by the copyright owner, its agent, or the law.

## 5. Statement of accuracy

I state that the information in this notification is accurate and, under
penalty of perjury, that I am the copyright owner, or am authorized to act
on behalf of the owner, of an exclusive right that is allegedly infringed.

## 6. Authorization and signature

[FILL IN: confirm the signer below is the owner or a duly authorized agent.]

Signature: [FILL IN: full legal name of the copyright owner or authorized agent]
Date: [FILL IN: date of sending]

--
This notice was prepared with Piracy-Watch (https://github.com/Gjusev/piracy-watch).
The detection evidence above was found by automated search and manually
reviewed by the complainant before sending.
"""


def render_host_email(config: Config, finding: Finding) -> str:
    """Generic abuse/DMCA email for non-GitHub hosts."""
    v = config.vendor
    return f"""To: abuse@[host-of-url]
Subject: DMCA Takedown Request — unauthorized distribution of {finding.product}

Hello,

We have detected the unauthorized distribution of our copyrighted software
on your service. Details:

{_blockquote_finding(finding)}

We request that you remove or disable access to the infringing material.
This message is sent pursuant to Section 512(c) of the DMCA (17 U.S.C.
§ 512(c)) or, for EU hosts, Article 17 BDSG/DSM Regulation as applicable.

Complainant: {v.name} ({v.email})
Address: {v.address or "[FILL IN: postal address]"}

[FILL IN before sending: describe the copyrighted work and attach evidence
of ownership. Verify the URL actually infringes — see checklist.md.]

Regards,
{v.name}
"""


def render_checklist(config: Config, finding: Finding) -> str:
    """The human checklist: what to verify before any notice is sent."""
    return f"""# Takedown checklist — {finding.product} / {finding.location}

Detected: {finding.first_seen} · Confidence: **{finding.confidence}**

## 1. Verify the infringement manually (required)

- [ ] Open {finding.url} and confirm what is actually there.
- [ ] Does it contain or distribute **{finding.product}** itself (binaries,
      cracked builds, keygens), or only mention it (docs, issue, meme)?
      A matched build string alone can appear in a bug report — do not
      send a notice for non-infringing content.
- [ ] For GitHub repos: check the default branch *and* releases/tags
      (code search only indexes the default branch).
- [ ] Screenshot the infringing content (with URL visible) and archive the
      page — content disappears once notified.

## 2. Confirm your standing

- [ ] You own, or represent, the copyright in the infringed work.
- [ ] Record what the copyrighted work is: [FILL IN: product, version,
      registration number if any].

## 3. Choose the notice

- GitHub content → send `github-dmca-notice.md` to **dmca@github.com**
  (all required policy elements are pre-filled; complete every
  `[FILL IN]` field first).
- Other hosts → send `host-abuse-email.txt` to the host's **abuse@**
  address (the domain of the URL). For registrars/CDNs, use their
  published abuse form instead.
- Repeat infringement / ignored notice → escalate to the host's legal
  department and consider the Lumen Database (lumendatabase.org) to see
  prior notices.

## 4. After sending

- Mark the finding ``notified``: `piracy-watch status {finding.finding_id} notified`
- Expect 1–6 weeks on GitHub; refusals can be appealed per GitHub's
  DMCA policy (counter-notice process exists — keep evidence).
- Mark ``resolved`` when content is gone: `piracy-watch status {finding.finding_id} resolved`

*This checklist is not legal advice. For substantial damages or
counter-notices, consult a lawyer.*
"""


def generate_kit(config: Config, finding: Finding, out_dir: Path) -> Path:
    """Write the DMCA kit for one finding; returns the kit directory."""
    target = kit_dir(out_dir, finding)
    target.mkdir(parents=True, exist_ok=True)
    (target / "README.md").write_text(render_checklist(config, finding), encoding="utf-8")
    (target / "github-dmca-notice.md").write_text(render_github_notice(config, finding), encoding="utf-8")
    (target / "host-abuse-email.txt").write_text(render_host_email(config, finding), encoding="utf-8")
    evidence = finding.to_dict()
    evidence["vendor"] = {
        "name": config.vendor.name,
        "email": config.vendor.email,
    }
    (target / "evidence.json").write_text(
        json.dumps(evidence, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target
