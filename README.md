# rAIdio.bot — Software Bill of Materials

Public, machine-readable SBOMs for [rAIdio.bot](https://store.steampowered.com/app/4600000) releases. Every release gets a CycloneDX 1.5 JSON covering every Rust crate, NPM package, Python dependency, ComfyUI custom node, AI model, and system tool shipped in the binary and its bundled backend.

## Current

| Release | Format | File | Components |
|---------|--------|------|------------|
| **RC1-UAT1.11** | CycloneDX 1.5 JSON | [releases/RC1-UAT1.11](https://github.com/rAIdio-bot/sbom/tree/main/releases/RC1-UAT1.11) | 800 |
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

## Fetch URLs

**GitHub release asset** (preferred for OSPO feeds):
<https://github.com/rAIdio-bot/sbom/releases/download/RC1-UAT1.11/rAIdio.bot-RC1-UAT1.11.cdx.json>

**Raw stable path** (for tools that pin to a directory):
<https://raw.githubusercontent.com/rAIdio-bot/sbom/main/releases/RC1-UAT1.11/rAIdio.bot-RC1-UAT1.11.cdx.json>

Both URLs are unauthenticated and permanent.

## What's inside each SBOM

- **Rust crates** linked into the Tauri binary — pinned by crate version from `cargo metadata`.
- **NPM packages** bundled into the Svelte frontend — pinned by the resolved version in `package-lock.json`.
- **Python dependencies** in the bundled ComfyUI backend we vendor (`torchcodec`, `opencv-python-headless`, `opencc-python-reimplemented`, …) — pinned to exact installed versions.
- **ComfyUI core + custom nodes** — pinned to upstream release tag (ComfyUI itself) or the HEAD SHA of our [memescreamer](https://github.com/memescreamer) mirror that feeds the Steam content depot, or [rAIdio-bot/rAIdio-nodes](https://github.com/rAIdio-bot/rAIdio-nodes) for our own patches.
- **AI models** distributed via the Steam content depot — pinned to HuggingFace revision SHA of the `memescreamer/*` HF mirror that carries the actual model files.
- **System tools** (ffmpeg, yt-dlp, …) — pinned to shipped executable version.

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

The SBOM is not yet signed. The rAIdio.bot app's C2PA provenance key (ES256, per-install) could be extended to sign SBOM artifacts in a later release. Tracked as future work alongside the TSA (trusted timestamp authority) integration. This does not affect SBOM validity — the content is fetchable from a known URL with a known repo owner — but a signed manifest would let downstream consumers prove the file came from us and was not modified in transit.

## Contact

Issues, additional format requests, or errata: open an issue on this repository or email `info@rAIdio.bot`.
