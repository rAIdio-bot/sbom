# rAIdio.bot — Software Bill of Materials

Public, machine-readable SBOMs for [rAIdio.bot](https://store.steampowered.com/app/4600000) releases. Every release gets a CycloneDX 1.5 JSON covering every Rust crate, NPM package, Python dependency, ComfyUI custom node, AI model, and system tool shipped in the binary and its bundled backend.

## Where to look for a specific component

`NOTICES.txt` has grown past 190,000 lines (~1,000+ components). To find any single component, use the **Table of Contents at the top of [`NOTICES.txt`](NOTICES.txt)** — every component is listed alphabetically with the line number where its block starts. For markdown reading, [`NOTICES.md`](NOTICES.md) opens with a clickable per-component TOC linking to anchor headings. Ad-hoc Ctrl-F in the GitHub raw viewer is brittle at this file size; the TOC is faster and reliable.

For machine queries, [`sbom.json`](sbom.json) is the authoritative source — every component carries `purl`, `licenses`, embedded LICENSE text, and several `com.raidio.*` properties for filtering (`com.raidio.depot`, `com.raidio.runs-in`, `com.raidio.scan-coverage`, `com.raidio.embedded-in`).

## Canonical files (FOSS compliance)

For per-component **verbatim license texts and copyright notices** (what an OSPO scanner or legal reviewer needs for FOSS compliance audits):

- **[`sbom.json`](sbom.json)** — the canonical enriched CycloneDX 1.5 SBOM. Reflects the most recent release. Every non-proprietary component carries its full LICENSE / COPYING / NOTICE text under `licenses[].license.text` (base64-encoded UTF-8 plain text) and harvested copyright lines under `component.copyright`. The CycloneDX 1.5 spec field for both.
- **[`NOTICES.txt`](NOTICES.txt)** — plain-text rendering of `sbom.json` for human reading. UTF-8, English, per-component block. Derived from `sbom.json` at release time, never edited by hand.
- **[`enrich-report.txt`](enrich-report.txt)** — processing summary for the most recent enrichment run: counts by status, per-component failures, source-tag distribution.
- **[`drift-report.txt`](drift-report.txt)** — queue of components where the declared SPDX license disagrees with what the source LICENSE file actually says. Each entry needs a human-audit decision. While non-empty, the `steam/push.ps1` pipeline refuses to ship the next release.

**Methodology (per-category — precision matters here, per FOSS-compliance review feedback 2026-05-22):** [`tools/sbom_enrich.py`](tools/sbom_enrich.py) (mirrored here for public auditability; the source-of-truth copy runs from the build pipeline) resolves each component's source to one of several fetch plans depending on its `raidio:category`. Stdlib-only Python; no external dependencies; deterministic and reproducible.

| Category | Source resolution | What we extract |
|---|---|---|
| Rust Crates | crates.io `.crate` tarball | LICENSE-named files at root + sample of source-header copyrights (max 300 files × first 50 lines each) |
| NPM Packages | npm registry tarball | LICENSE-named files at root |
| Python Packages | PyPI sdist preferred, wheel fallback. For PEP 440 `+local` segment packages (torch family — `+cu128` etc.) the GitHub release-tag source tarball preferred over the wheel, because wheels are binary blobs that hide the source tree | LICENSE-named files at root + sample of source-header copyrights (max 300 files × first 50 lines each) |
| AI Models | HuggingFace mirror probe for LICENSE-named files. If absent (our memescreamer mirrors carry weights only), fall back to the `upstream_source_url` (set via `tools/generate_sbom.py:AI_MODELS`) and probe that GitHub repo's root for LICENSE-named files instead | LICENSE / NOTICE / COPYING files at upstream repo root |
| ComfyUI Nodes | GitHub raw single-file probe at the pinned revision SHA | LICENSE-named files at repo root |
| Embedded Python Overrides | Same as ComfyUI Nodes | LICENSE-named files at repo root |
| System Tools | `tools/sbom_enrich_system_tools.json` curation map (ffmpeg, CPython) names the source tarball + which LICENSE files to extract | Curated list of LICENSE / COPYING / CREDITS files in declaration order |

For every category, every extracted LICENSE / COPYING / NOTICE file is base64-embedded into the SBOM's `licenses[].license.text` field verbatim. Copyright lines are harvested from the LICENSE bodies AND (where source-header sampling is in scope) from the first 50 lines of up to 300 source files matching the source-extension regex, and aggregated into `component.copyright`.

**Source-header sampling caveat.** The 300-file cap is sufficient for most components (~95% have fewer source files). For large multi-vendor projects like torchvision, the cap is NOT sufficient — vendored sub-trees beyond the first 300 sampled files are not reached. The new `com.raidio.scan-coverage` property on each component (added 2026-05-22) records the actual coverage tier (`license-only` / `sampled` / `exhaustive`) so a reviewer can filter the SBOM to find every component whose scan was incomplete.

**ScanCode-style file-level evidence** in the CycloneDX `evidence[]` field is populated by the offline [`tools/sbom_deep_scan.py`](tools/sbom_deep_scan.py) pass for components where the sampling cap is insufficient. Deep-scan runs at release cadence and feeds the in-pipeline enricher with cached source archives.

## Historical releases

The per-release `releases/RC-1-Gold-0.X/` tree below is the audit trail — what shipped, when. Those snapshots stay unenriched as the historical record; `sbom.json` at the root is the current truth.

## Current

Releases `0.16` through `0.21` were Steam-pushed without their SBOM
artefacts being archived to this repository at push time. The
dependency state at those tags is reconstructable from source via the
SBOM pipeline described in `## Generation` below; on-request
reconstruction is available via the issue tracker.

| Release | Format | File | Components |
|---------|--------|------|------------|
| **RC-1-Gold-0.36** | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.36](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.36) | 996 |
| RC-1-Gold-0.35 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.35](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.35) | 1037 |
| RC-1-Gold-0.34 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.34](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.34) | 1037 |
| RC-1-Gold-0.33 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.33](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.33) | 1037 |
| RC-1-Gold-0.32 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.32](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.32) | 824 |
| RC-1-Gold-0.31 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.31](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.31) | 815 |
| RC-1-Gold-0.30 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.30](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.30) | 815 |
| RC-1-Gold-0.29 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.29](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.29) | 815 |
| RC-1-Gold-0.28 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.28](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.28) | 815 |
| RC-1-Gold-0.27 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.27](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.27) | 815 |
| RC-1-Gold-0.26 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.26](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.26) | 815 |
| RC-1-Gold-0.25 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.25](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.25) | 815 |
| RC-1-Gold-0.24 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.24](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.24) | 815 |
| RC-1-Gold-0.23 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.23](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.23) | 815 |
| RC-1-Gold-0.22 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.22](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.22) | 815 |
| RC-1-Gold-0.21 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.20 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.19 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.18 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.17 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.16 | CycloneDX 1.5 JSON | (not archived at push time) | — |
| RC-1-Gold-0.15 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.15](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.15) | 815 |
| RC-1-Gold-0.14 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.14](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.14) | 815 |
| RC-1-Gold-0.13 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.13](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.13) | 815 |
| RC-1-Gold-0.12 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.12](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.12) | 815 |
| RC-1-Gold-0.11 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.11](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.11) | 815 |
| RC-1-Gold-0.10 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.10](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.10) | 815 |
| RC-1-Gold-0.9 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.9](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.9) | 815 |
| RC-1-Gold-0.8 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.8](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.8) | 815 |
| RC-1-Gold-0.7 | CycloneDX 1.5 JSON | [releases/RC-1-Gold-0.7](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC-1-Gold-0.7) | 815 |
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