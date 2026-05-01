# rAIdio.bot — Software Bill of Materials

Public, machine-readable SBOMs for [rAIdio.bot](https://store.steampowered.com/app/4600000) releases. Every release gets a CycloneDX 1.5 JSON covering every Rust crate, NPM package, Python dependency, ComfyUI custom node, AI model, and system tool shipped in the binary and its bundled backend.

## Current

| Release | Format | File | Components |
|---------|--------|------|------------|
| **RC-1-Gold-0.7** | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.7](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.7) | 815 |
| RC-1-Gold-0.6 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.6](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.6) | 814 |
| RC-1-Gold-0.5 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.5](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.5) | 807 |
| RC-1-Gold-0.4 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.4](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.4) | 805 |
| RC-1-Gold-0.3 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.3](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.3) | 805 |
| RC-1-Gold-0.2 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.2](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.2) | 805 |
| RC1-UAT1.17 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.17](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.17) | 803 |
| RC1-UAT1.16 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.16](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.16) | 803 |
| RC1-UAT1.15 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.15](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.15) | 801 |
| RC1-UAT1.14 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.14](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.14) | 801 |
| RC1-UAT1.13 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.13](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.13) | 801 |
| RC1-UAT1.12 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.12](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.12) | 801 |
| RC1-UAT1.11 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.11](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.11) | 801 |
| RC1-UAT1.10 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.10](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.10) | 801 |
| RC1-UAT1.9 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.9](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.9) | 801 |
| RC1-UAT1.8 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.8](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.8) | 801 |
| RC1-UAT1.7 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.7](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.7) | 801 |
| RC1-UAT1.6 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.6](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.6) | 801 |
| RC1-UAT1.5 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.5](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.5) | 801 |
| RC1-UAT1.4 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.4](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.4) | 801 |
| RC1-UAT1.3 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.3](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.3) | 790 |
| RC1-UAT1.2 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.2](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.2) | 790 |
| RC1-UAT1.1 | CycloneDX 1.5 JSON | [releases/RC1-UAT1.1](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.1) | 790 |

> **License audit erratum (2026-04-26):** A license audit on
> 2026-04-26 corrected six material errors and one provenance
> error in SBOMs published prior to today. The current
> `RC1-UAT1.16` CycloneDX has been regenerated with the
> corrected data. Older RCs have not been retroactively edited —
> see [ERRATA_2026-04-26.md](./ERRATA_2026-04-26.md) for the
> authoritative correction record.

## Verify your install

Every release from RC1-UAT1.13 onward publishes the sha256 of the
shipped `raidio-bot.exe` here. Confirm the binary on your machine
matches what was released:

```powershell
$tag = 'RC-1-Gold-0.2'   # change to your installed RC (see About dialog)
$exe = Join-Path ${env:ProgramFiles(x86)} 'Steam\steamapps\common\rAIdio.bot\raidio-bot.exe'
$local     = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLower()
$published = (Invoke-RestMethod "https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/$tag/SHA256SUMS").Split(' ')[0]
if ($local -eq $published) { 'OK — matches release' } else { "MISMATCH — local $local vs published $published" }
```

If the values differ, the binary on disk is not the released build —
either the install is corrupted, an update is in flight, or the binary
has been replaced. Re-install from Steam or report at the security
contact in [SECURITY.md][security-md] of the source repo.

A `MISMATCH` is **not** by itself proof of compromise — Steam
sometimes reshuffles content depots and an old binary may linger after
an update. Reproduce on a clean install before raising a security
issue.

This is a hash-publication mechanism. It proves the file you have
matches what we released; it does not prove we are who we say we are.

[security-md]: ./SECURITY.md

## Fetch URLs

**GitHub release asset** (preferred for OSPO feeds):
<https://github.com/rAIdio-bot/sbom/releases/download/RC-1-Gold-0.2/rAIdio.bot-RC-1-Gold-0.2.cdx.json>

**Raw stable path** (for tools that pin to a directory):
<https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/RC-1-Gold-0.2/rAIdio.bot-RC-1-Gold-0.2.cdx.json>

Both URLs are unauthenticated and permanent.

## What's inside each SBOM

- **Rust crates** linked into the Tauri binary — pinned by crate version from `cargo metadata`.
- **NPM packages** bundled into the Svelte frontend — pinned by the resolved version in `package-lock.json`.
- **Python dependencies** in the bundled ComfyUI backend we vendor (`torchcodec`, `opencv-python-headless`, `opencc-python-reimplemented`, …) — pinned to exact installed versions.
- **ComfyUI core + custom nodes** — pinned to upstream release tag (ComfyUI itself) or the HEAD SHA of our [memescreamer](https://github.com/memescreamer) mirror that feeds the Steam content depot, or [rAIdio-bot/rAIdio-nodes](https://github.com/rAIdio-bot/rAIdio-nodes) for our own patches.
- **AI models** distributed via the Steam content depot — pinned to HuggingFace revision SHA of the `memescreamer/*` HF mirror that carries the actual model files.
- **System tools** (ffmpeg, …) — pinned to shipped executable version.

Each component carries an SPDX license identifier, a package URL (purl), a homepage where available, and a `raidio:category` property indicating which of the six layers above it belongs to.

## Format choice

CycloneDX 1.5 JSON. One of the two CISA minimum-elements-compliant SBOM formats (SPDX is the other); ingests natively in Dependency-Track, OWASP Dependency-Check, Chainguard, Snyk, Grype, Syft, and most modern OSPO tooling without conversion. If someone specifically asks for SPDX 2.3, the generator can emit it — open an issue.

## Verification

Ingest into a compatible OSPO tool:

| Tool | Command |
|------|---------|
| OWASP Dependency-Track | upload via the web UI or API |
| `cyclonedx-cli` | `cyclonedx validate --input-file rAIdio.bot-RC1-UAT1.11.cdx.json` |
| `grype` / `syft` | `grype sbom:rAIdio.bot-RC1-UAT1.11.cdx.json` |

## Generation

The SBOM pipeline lives in the source repo and is reproducible from scratch:

1. `tools/generate_sbom.py` builds an internal `sbom_licenses.json` from `cargo metadata`, `package.json`, and a curated list of non-package-manager components (AI models, ComfyUI nodes, system tools) — all versions pinned to real identifiers, no `"latest"` strings.
2. `tools/generate_cyclonedx.py` converts that file into CycloneDX 1.5 JSON.

Both are stdlib-only Python; no paid tooling, no external service calls at generation time.

## Signing

The SBOM is not signed. Integrity rests on fetching it from this
repository over HTTPS; the GitHub commit history is the audit trail.

## Contact

Issues, additional format requests, or errata: open an issue on this repository or email `info@rAIdio.bot`.
