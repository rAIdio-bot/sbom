# VirusTotal Integration

Every Steam release submits the native binaries it ships to VirusTotal,
captures the verdict per binary, and publishes the result alongside the
SBOM. A daily GitHub Actions workflow on `rAIdio-bot/sbom` re-polls each
(release, binary) pair so retro-flags (an AV vendor adding a heuristic
next month and our shipped python.exe lighting up) are caught before
users do.

## Which binaries are scanned

| Binary | Depot | Why scan |
|--------|-------|----------|
| `raidio-bot.exe` | 1 (app) | Unique per-release bytes compiled by us. |
| `steam_api64.dll` | 1 (app) | Bundled Valve binary — small, low effort to include. |
| `python.exe` | 2 (content) | Bundled CPython interpreter. High impact if tampered. |
| `ffmpeg.exe` | 2 (content) | Tool we explicitly bundle and invoke. |

What we do NOT submit:

- **Native DLLs from upstream wheels** (PyTorch, OpenCV, etc.) — the SBOM
  pins them by exact PyPI hash, which is a stronger guarantee than VT's
  "no engine flagged this." Scanning would just re-confirm what
  100,000 other PyTorch installs already confirmed.
- **AI model weights** (`.safetensors`, `.pt`, `.ckpt`, `.pkl`) — VT's AV
  engines don't meaningfully analyse model files. The defense for this
  layer is the safetensors-only loader + picklescan / fickling
  (a separate Item 2 hardening track).
- **Python source files** — VT can't scan source meaningfully; tampering
  shows up as a hash mismatch against the pinned wheel.

## Why

GPU-heavy ML applications routinely false-positive on heuristic
engines. The threat model is "users see a SmartScreen warning or a
red Defender popup and assume the binary is malicious." We want to
know about that *before* the support emails start, so we can pre-empt
with a published note.

VT also detects real compromise. If a future release of ours gets
flagged by Microsoft Defender or one of the major vendors, that is
either a reproducible false positive we need to file with the vendor,
or an actual problem that needs the binary pulled. Both deserve fast
notice.

## How it works

```
[push.ps1 step 5]                  [GitHub Actions: daily cron]
     |                                       |
     v                                       v
  POST /files  -> VT analyses          GET /files/{sha256}
  GET /files/{sha256}                  diff vs virustotal_state.json
  write virustotal.json                emit decisions.json
                                       gh issue create / comment / escalate
                                       commit state file
```

### Per-release artefacts

One JSON per binary. `releases/<tag>/virustotal_<filename>.json`:

```json
{
  "tag": "RC1-UAT1.16",
  "filename": "raidio-bot.exe",
  "sha256": "...",
  "vt_link": "https://www.virustotal.com/gui/file/<sha256>",
  "fetched_at": "2026-04-26T13:00:00Z",
  "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 5, "undetected": 65},
  "last_analysis_results": { "Microsoft": {"category": "undetected", ...}, ... }
}
```

Example release listing:

```
releases/RC1-UAT1.16/
  rAIdio.bot-RC1-UAT1.16.cdx.json
  hashes.json
  SHA256SUMS
  virustotal_raidio-bot.exe.json
  virustotal_steam_api64.dll.json
  virustotal_python.exe.json
  virustotal_ffmpeg.exe.json
```

The poll script tracks each (tag, filename) pair as a separate state
entry and opens a separate GitHub issue per pair, so a Defender flag
on `python.exe` doesn't conflate with a Trapmine flag on
`raidio-bot.exe`.

### Daily monitor

`.github/workflows/virustotal_monitor.yml` in the sbom repo runs
`tools/virustotal_poll.py` once a day. The poll script reads each
`virustotal.json`, fetches the current state from VT, compares against
`tools/virustotal_state.json`, and emits decisions consumed by the
workflow's `gh issue` calls.

## Alert tiers

Tier logic lives in `tools/virustotal_poll.py:compute_tier`. From least
to most severe:

| Tier | Trigger | GitHub action | Email? |
|------|---------|---------------|--------|
| `silent` | Stats unchanged since last poll. | None — timestamp only. | No |
| `baseline` | First scan after a release. | Issue created, label `vt-baseline`. | No |
| `minor` | `malicious + suspicious` ticked up by 1. | Comment on the existing issue. | No |
| `alert` | `malicious + suspicious` ≥ 3. | Escalate: label `vt-alert`, assign + @mention maintainer. | **Yes** |
| `major` | ESET / Kaspersky / BitDefender / Sophos / F-Secure / FireEye / Avast / AVG flags. | Escalate: label `vt-major`, assign + @mention. | **Yes** |
| `defender` | Microsoft Defender flags. | Escalate: label `vt-defender` + `priority/critical`, assign + @mention. | **Yes** |

Defender is the highest-impact tier because ~90% of Windows users run
it; a Defender flag means SmartScreen warnings and direct user impact.

GitHub mails the maintainer on the email-emitting tiers via two
independent mechanisms — assignee notification *and* `@mention` — so
the alert lands even with aggressive notification filters.

## Single-maintainer config

The maintainer routing lives in `tools/virustotal_poll.py`:

```python
MAINTAINERS = ["neitzert"]   # GitHub usernames; will be assigned issues
MENTION = "@neitzert"        # Literal string interpolated into issue bodies
```

To add a co-maintainer, append to both lists. No workflow YAML changes
needed.

## Privacy disclosure

**Uploading a file to VT shares it with VirusTotal enterprise
customers** — security firms, AV vendors, and threat researchers. For
rAIdio.bot specifically this is fine: the exe ships publicly via Steam
to anyone who installs the game, so confidentiality is not lost by VT
sharing it with security professionals.

This concern would matter if we ever submitted artefacts that were
**not** publicly distributed (internal builds, DRM-bound extracts,
user-trained voices). The current pipeline submits only the public
Steam-shipped exe; do not extend it to user data without re-evaluating
this section.

## Failure modes

| Failure | Behaviour |
|---------|-----------|
| API key unset at submit time | The release proceeds without VT submission; the next daily poll picks up no new file but does not fail. |
| VT API returns 5xx during submission | Submission is best-effort and never gates a release. The next daily poll retries via the cached hash. |
| VT analysis times out | Submission is logged as incomplete; manual re-run available. |
| Workflow secret missing | Workflow fails on the poll step with an explicit message; no issues are opened or missed. |
| `@mention` not delivered | Assignee notification still fires; two-channel design assumes either path can fail. |
