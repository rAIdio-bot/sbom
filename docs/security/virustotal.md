# VirusTotal Integration

Every Steam release submits the native binaries it ships to VirusTotal,
captures the verdict per binary, and publishes the result alongside the
SBOM in this repo (`releases/<tag>/virustotal_<binary>.json`). The
published results are re-checked over time, so a retro-flag — an AV
vendor adding a heuristic next month and our shipped `python.exe`
lighting up — is caught and can be pre-empted with a published note.

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
  layer is the safetensors-only loader + picklescan / fickling.
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
either a reproducible false positive we file with the vendor, or an
actual problem that needs the binary pulled. Both deserve fast notice.

## Known false positives

GPU-heavy, **unsigned**, freshly-compiled binaries with low prevalence routinely
trip *machine-learning* AV heuristics — the engine guesses from the binary's
novelty, not a signature match. We have seen, and assessed as false positives:

- **Microsoft `Trojan:Win32/Wacatac.B!ml`** on `raidio-bot.exe` (first seen
  RC-1-Gold-0.65, 2026-06-08). The `!ml` suffix is a machine-learning verdict;
  `Wacatac.B!ml` is the most common Defender false positive for new, unsigned,
  low-prevalence software. **Local Windows Defender — real-time protection on,
  current signatures — does not flag the binary**; the verdict comes only from
  VirusTotal's more aggressive cloud-ML configuration.
- **Trapmine `malicious.moderate.ml.score`** — an ML risk score, recurring.
- **Kaspersky** heuristic (`HEUR…`) — historically, on earlier builds.

How we distinguish these from a real detection: they are ML/heuristic (not
signature), they appear on a brand-new build hash while the previous build's
hash scanned clean, they are 2–3 engines out of ~70 (the rest undetected), and
the on-machine Defender that users actually run does not quarantine the file. A
genuine compromise would light up multiple signature engines, not a couple of ML
guesses. (The 0.65 binary differed from 0.64 by a single frontend source file.)

**Durable fix: Authenticode code-signing** (see [signing.md](signing.md)). A
signed, reputation-bearing binary bypasses the prevalence heuristic and clears
the vast majority of these `!ml` flags. Until signing ships, each new build hash
re-rolls the ML and may be flagged transiently until prevalence accrues.

## Per-release artefacts

One JSON per binary, `releases/<tag>/virustotal_<filename>.json`:

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

Each (tag, binary) pair is recorded independently, so a Defender flag on
`python.exe` doesn't conflate with a heuristic flag on `raidio-bot.exe`.

## Privacy disclosure

**Uploading a file to VT shares it with VirusTotal enterprise
customers** — security firms, AV vendors, and threat researchers. For
rAIdio.bot specifically this is fine: the binaries ship publicly via
Steam to anyone who installs the app, so confidentiality is not lost by
VT sharing them with security professionals.

This concern would matter if we ever submitted artefacts that were
**not** publicly distributed (internal builds, DRM-bound extracts,
user-trained voices). The pipeline submits only the public
Steam-shipped binaries; do not extend it to user data without
re-evaluating this section.
