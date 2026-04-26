# Transparency

rAIdio.bot is a local-first, zero-telemetry desktop application. The
following artefacts are published per release on public GitHub so any
user, auditor, or researcher can independently verify what was shipped.

Single landing page: <https://github.com/rAIdio-bot/sbom>

## Per-release artefacts

Under `releases/<tag>/` in the [sbom repository][sbom-repo]:

| File | Purpose |
|------|---------|
| `rAIdio.bot-<tag>.cdx.json` | CycloneDX 1.5 SBOM. Every Rust crate, NPM package, Python dep, ComfyUI custom node, AI model, system tool. ~801 components, all version-pinned. |
| `hashes.json` | Machine-readable: tag, AppID, depot ID, raw BuildID, sha256(s) of shipped file(s), generated_at timestamp. |
| `SHA256SUMS` | Linux-distro-style plain text. `sha256 *filename` lines. Compatible with `sha256sum -c`. |
| `virustotal.json` | VirusTotal scan verdict at release time. Daily monitor in the sbom repo's Actions polls for retro-flags; see [virustotal.md](./virustotal.md). |

Future per-release additions (deferred behind hardware procurement):

| File | Phase |
|------|-------|
| `signing-cert.pem` | Phase 2 — Authenticode EV cert public certificate. |
| `<tag>.c2pa` | Phase 2 — detached C2PA manifest for the binary, signed with the same identity used for output provenance. |

## Repository-level artefacts

| Source | Purpose |
|--------|---------|
| [`rAIdio-bot/sbom`][sbom-repo] | Per-release SBOM + hashes. Public, append-only history. |
| [`rAIdio-bot/manual`][manual-repo] | Public mirror of `docs/manual/*` — the in-app help text. Lets users read what the app contains without installing it. |
| [`rAIdio-bot/rAIdio-nodes`][nodes-repo] | Source of GPL-3.0 / Apache-2.0 patched ComfyUI custom nodes shipped in the AI content depot. Required for source-availability compliance. |
| [`SECURITY.md`](../../SECURITY.md) | Researcher contact, scope, advisory channel. |

## What this is *not*

- **A signed-binary attestation.** Phase 1 publishes hashes on a single
  channel (GitHub). Defense against that channel being silently rewritten
  is GitHub's commit audit log + the public attention of users actually
  checking. Phase 2 adds Authenticode signing with a hardware-backed EV
  cert as a second independent channel.
- **A telemetry feed.** rAIdio.bot does not phone home. The transparency
  artefacts here are *static publications* the user fetches; the app
  itself does not contact this repo at runtime.

## Verification quickstart

The recipe a user follows to confirm their installed binary matches the
release:

```powershell
# 1. Compute the local hash.
$tag = 'RC1-UAT1.16'
$exe = Join-Path ${env:ProgramFiles(x86)} 'Steam\steamapps\common\rAIdio.bot\raidio-bot.exe'
$local = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()

# 2. Fetch the published hash.
$published = (Invoke-RestMethod "https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/$tag/SHA256SUMS").Split(' ')[0]

# 3. Compare.
if ($local -eq $published) { 'OK — matches release' } else { "MISMATCH — local $local vs published $published" }
```

Adjust `$tag` to the RC you have installed (visible in the app's About
dialog).

[sbom-repo]: https://github.com/rAIdio-bot/sbom
[manual-repo]: https://github.com/rAIdio-bot/manual
[nodes-repo]: https://github.com/rAIdio-bot/rAIdio-nodes
