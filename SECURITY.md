# Security Policy

## Reporting a vulnerability

Email both addresses in parallel; whichever is monitored that day will
respond fastest.

- `info@rAIdio.bot` — general intake (founder + ops).

Please give a working description of the issue, steps to reproduce, and
your expected impact. PGP is welcome but not required; we will not gate
acknowledgement on it.

We aim to respond within **3 business days** for any plausible report
and to ship a fix within **30 days** for confirmed vulnerabilities, with
escalated cadence for active exploitation.

## Scope

In scope:

- The Steam-distributed Windows desktop binary `raidio-bot.exe` and its
  bundled backend (Depots 4600001 + 4600002 + 4611720).
- The build pipeline that produces those binaries
  (`tools/generate_sbom.py`, `steam/push.ps1`, `build.ps1`).
- The public artefact repositories at
  [github.com/rAIdio-bot](https://github.com/rAIdio-bot/) — `sbom`,
  `manual`, `rAIdio-nodes`.

Out of scope:

- Third-party code we ship under our own license disclosure
  (ComfyUI, AI models, system tools) — please report those upstream;
  we will mirror your finding into our SBOM if it affects a shipped
  version.
- Social-engineering, physical access to a developer's machine, or
  attacks requiring a pre-compromised environment.
- Reports from automated scanners with no proof of exploitability —
  please verify before reporting.

## Verifying you have the genuine binary

If you suspect a binary on your machine has been tampered with, see
[docs/security/transparency.md](./docs/security/transparency.md) for
the verification recipe. Short version: compute `sha256` of your local
exe, compare against the published `SHA256SUMS` for your release tag at
[github.com/rAIdio-bot/sbom](https://github.com/rAIdio-bot/sbom).

## Advisories

No security advisories have been published. Advisories live in this
section as dated entries with a tagged release on the
[sbom repo](https://github.com/rAIdio-bot/sbom/releases).

## Continuous monitoring

Every release is submitted to [VirusTotal](https://www.virustotal.com)
at push time and re-polled daily by a workflow in the sbom repo. Flags
from Microsoft Defender or any major AV vendor (ESET / Kaspersky /
BitDefender / Sophos / F-Secure) escalate to a tracked GitHub issue.
See [docs/security/virustotal.md](./docs/security/virustotal.md) for
the full alert tier table.

## What we will and will not do

We will:

- Acknowledge your report.
- Keep you updated on triage and remediation.
- Credit you in the advisory if you want, or omit your name if you
  prefer.

We will not:

- Pursue legal action against good-faith researchers operating within
  the scope above.
- Demand you withhold disclosure beyond a reasonable patch-and-ship
  window.

## Bounty

There is no formal monetary bounty programme at this time. We will
consider per-report rewards on impact for confirmed vulnerabilities.
This is funded by the founder out of pocket — please be patient with
the budget.
