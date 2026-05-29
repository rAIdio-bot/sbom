# ScanCode full-pass deviations report

Full ScanCode v32.5.0 scan over every shipped component bucket (Rust crates, NPM packages, Python deps, ComfyUI nodes, embedded-Python overrides). Detected per-component dominant license expression compared against the SBOM-declared license. Known-false-positive patterns from Till Jaeger's 2026-05-27 guidance are filtered automatically (GPL appendix "or any later version" recommendation; phantom commercial-OR disjuncts; trivially-redundant AND-conjunctions).

## Summary

- Components matched to SBOM: **224**
  - ACK: 91
  - MISMATCH: 21
  - NO-DETECTION: 110
  - CURATED (operator-documented rationale): 2
- Unaccounted scanned dirs (in source tree but not in SBOM): **1669**

## CURATED (2)

Operator-documented overrides in `tools/sbom_drift_curation.json`.
ScanCode's detection differs from the declared license intentionally.

- `SeedVC-ComfyUI` `0f6481215b64`: declared `GPL-3.0`, detected `MIT`
  - AIFSH upstream has NO LICENSE file. The memescreamer mirror added an MIT LICENSE (Copyright 2024 memescreamer) but that's not a legally valid relicensing of upstream code. The custom node imports seed...
- `comfyui-frontend-package` `1.38.14`: declared `GPL-3.0`, detected `MIT`
  - Conservative-declaration override (same pattern as SeedVC-ComfyUI@0f6481215b64). The pip package `comfyui-frontend-package` is itself published as MIT on PyPI (LICENSE-free dist-info; PyPI metadata sa...

## MISMATCH (21)

These warrant manual review. The detected license differs from the declared license after the false-positive filters.

| Bucket | Component | Version | Declared | Detected | LICENSE file | Files |
|--------|-----------|---------|----------|----------|--------------|-------|
| npm | `vite` | `6.0.0` | `MIT` | `(MIT AND Apache-2.0 AND BSD-2-Clause AND CC0-1.0) AND MIT AND ISC AND BSD-2-Clause AND (BSD-2-Clause AND MIT) AND (MIT AND CC0-1.0) AND CC0-1.0` | ✓ | 35 |
| npm | `vitest` | `4.1.4` | `MIT` | `(MIT AND BSD-3-Clause) AND MIT AND BSD-3-Clause AND ISC` | ✓ | 114 |
| python | `Cython` | `3.2.4` | `Apache-2.0` | `BSD-2-Clause` | — | 447 |
| python | `Pygments` | `2.19.2` | `BSD-2-Clause` | `BSD-3-Clause` | — | 676 |
| python | `comfyui-workflow-templates-media-other` | `0.3.121` | `MIT` | `Apache-2.0` | — | 237 |
| python | `demucs` | `4.0.1` | `MIT` | `BSD-3-Clause OR GPL-2.0-only` | — | 61 |
| python | `fastapi` | `0.135.1` | `MIT` | `Apache-2.0` | — | 101 |
| python | `fonttools` | `4.62.1` | `MIT` | `Apache-2.0` | — | 678 |
| python | `future` | `1.0.0` | `MIT` | `BSD-3-Clause` | — | 280 |
| python | `kiwisolver` | `1.5.0` | `BSD-3-Clause` | `BSD-2-Clause` | — | 7 |
| python | `matplotlib` | `3.10.8` | `PSF-2.0` | `OFL-1.1` | — | 796 |
| python | `numba` | `0.64.0` | `BSD-3-Clause` | `BSD-2-Clause` | — | 1513 |
| python | `numpy` | `2.2.6` | `BSD-3-Clause` | `(NCSA AND BSD-3-Clause) AND BSD-3-Clause` | ✓ | 1298 |
| python | `packaging` | `26.0` | `Apache-2.0 OR BSD-2-Clause` | `BSD-3-Clause OR Apache-2.0` | — | 35 |
| python | `parso` | `0.8.6` | `MIT` | `Python-2.0 AND MIT` | — | 52 |
| python | `pip` | `26.0.1` | `MIT` | `BSD-3-Clause` | — | 846 |
| python | `pyreadline3` | `3.5.4` | `BSD-3-Clause` | `BSD-2-Clause` | — | 85 |
| python | `setuptools` | `70.2.0` | `MIT` | `BSD-3-Clause OR Apache-2.0` | — | 426 |
| python | `srsly` | `2.5.2` | `MIT` | `BSD-3-Clause` | — | 252 |
| python | `tensorboardX` | `2.6.4` | `MIT` | `Apache-2.0` | — | 82 |
| python | `torchaudio` | `2.10.0` | `BSD-3-Clause` | `MIT` | — | 160 |

## NO-DETECTION (110)

ScanCode found no detectable license in any file. Most of these are tiny packages where the license is declared in metadata (Cargo.toml, package.json, METADATA) rather than in a LICENSE file or per-file header. Sample:

- `aiohappyeyeballs` `2.6.1` (declared `PSF-2.0`, 11 files, python)
- `aiohttp` `3.13.3` (declared `Apache-2.0 AND MIT`, 131 files, python)
- `aiosignal` `1.4.0` (declared `Apache-2.0`, 3 files, python)
- `annotated-doc` `0.0.4` (declared `MIT`, 5 files, python)
- `annotated-types` `0.7.0` (declared `MIT`, 5 files, python)
- `anyio` `4.12.1` (declared `MIT`, 85 files, python)
- `argbind` `0.3.9` (declared `MIT`, 4 files, python)
- `av` `16.1.0` (declared `BSD-3-Clause`, 245 files, python)
- `catalogue` `2.0.10` (declared `MIT`, 10 files, python)
- `certifi` `2026.2.25` (declared `MPL-2.0`, 8 files, python)
- `cffi` `2.0.0` (declared `MIT`, 40 files, python)
- `click` `8.3.1` (declared `BSD-3-Clause`, 35 files, python)
- `cloudpathlib` `0.23.0` (declared `MIT`, 59 files, python)
- `coloredlogs` `15.0.1` (declared `MIT`, 14 files, python)
- `comfy-aimdo` `0.1.8` (declared `GPL-3.0`, 9 files, python)
- `comfyui-embedded-docs` `0.4.1` (declared `GPL-3.0`, 7158 files, python)
- `comfyui-workflow-templates` `0.8.43` (declared `MIT`, 2 files, python)
- `comfyui-workflow-templates-core` `0.3.145` (declared `MIT`, 5 files, python)
- `comfyui-workflow-templates-media-api` `0.3.53` (declared `MIT`, 261 files, python)
- `comfyui-workflow-templates-media-image` `0.3.90` (declared `MIT`, 189 files, python)
- `comfyui-workflow-templates-media-video` `0.3.49` (declared `MIT`, 132 files, python)
- `confection` `0.1.5` (declared `MIT`, 15 files, python)
- `contourpy` `1.3.3` (declared `BSD-3-Clause`, 38 files, python)
- `ctranslate2` `4.7.1` (declared `MIT`, 52 files, python)
- `cutlet` `0.5.0` (declared `MIT`, 9 files, python)
- `cycler` `0.12.1` (declared `BSD-3-Clause`, 3 files, python)
- `docstring_parser` `0.17.0` (declared `MIT`, 37 files, python)
- `einops` `0.8.2` (declared `MIT`, 53 files, python)
- `faster-whisper` `1.2.1` (declared `MIT`, 19 files, python)
- `ffmpy` `1.0.0` (declared `MIT`, 5 files, python)
- ... and 80 more

## Unaccounted (1669)

Directories present in a source tree but not matched to any SBOM component. Common reasons: cargo cache holds extra crates beyond Cargo.lock; npm transitive subdirs; Python package import-name vs distribution-name mismatch (e.g. `PIL` vs `Pillow`, `cv2` vs `opencv-python-headless`); metadata `.dist-info` / `.egg-info` directories; pip shadow-update `~`-prefixed directories.

- Total: 1669
- After noise-stripping: 1429

Sample of substantive unaccounted dirs:
- `.package-lock.json` (npm, 1 files, detected `MIT AND MIT-0 AND Apache-2.0 AND (Apache-2.0 OR MIT) AND (MIT OR Apache-2.0) AND BSD-2-Clause AND BSD-3-Clause AND ISC AND BlueOak-1.0.0 AND CC0-1.0`)
- `.vite-temp` (npm, 0 files, detected `none`)
- `.bin` (npm, 48 files, detected `none`)
- `.vite` (npm, 1 files, detected `none`)
- `@asamuzakjp` (npm, 77 files, detected `MIT`)
- `@bramus` (npm, 16 files, detected `MIT`)
- `@csstools` (npm, 36 files, detected `MIT`)
- `@esbuild` (npm, 3 files, detected `MIT`)
- `@eslint` (npm, 56 files, detected `Apache-2.0`)
- `@eslint-community` (npm, 26 files, detected `MIT`)
- `@exodus` (npm, 75 files, detected `MIT`)
- `@humanfs` (npm, 25 files, detected `Apache-2.0`)
- `@humanwhocodes` (npm, 19 files, detected `Apache-2.0`)
- `@jridgewell` (npm, 150 files, detected `MIT`)
- `@polka` (npm, 5 files, detected `MIT`)
- `@rollup` (npm, 6 files, detected `MIT`)
- `@standard-schema` (npm, 7 files, detected `MIT`)
- `@sveltejs` (npm, 50 files, detected `MIT`)
- `@tauri-apps` (npm, 96 files, detected `Apache-2.0 AND MIT`)
- `@types` (npm, 27 files, detected `MIT`)
- `@typescript-eslint` (npm, 14 files, detected `MIT`)
- `@vitest` (npm, 121 files, detected `MIT`)
- `acorn` (npm, 10 files, detected `MIT`)
- `acorn-jsx` (npm, 6 files, detected `MIT`)
- `ajv` (npm, 92 files, detected `MIT`)
- `aria-query` (npm, 157 files, detected `Apache-2.0`)
- `assertion-error` (npm, 5 files, detected `MIT`)
- `axobject-query` (npm, 134 files, detected `Apache-2.0`)
- `balanced-match` (npm, 13 files, detected `MIT`)
- `bidi-js` (npm, 17 files, detected `MIT`)
- ... and 1399 more

## ACK sample

91 components where the detected license matches the declared license (after FP filters). Not enumerated in full; first 25 for spot-checking:

- `eslint` `10.2.1`: declared `MIT` ✓
- `eslint-config-prettier` `10.1.8`: declared `MIT` ✓
- `eslint-plugin-svelte` `3.17.0`: declared `MIT` ✓
- `globals` `17.5.0`: declared `MIT` ✓
- `jsdom` `29.0.2`: declared `MIT` ✓
- `prettier` `3.8.3`: declared `MIT` ✓
- `prettier-plugin-svelte` `3.5.1`: declared `MIT` ✓
- `svelte` `5.0.0`: declared `MIT` ✓
- `svelte-eslint-parser` `1.6.0`: declared `MIT` ✓
- `wavesurfer.js` `7.12.5`: declared `BSD-3-Clause` ✓
- `00_rAIdio_rvc_patch` `65e4f95`: declared `GPL-3.0` ✓
- `00_rAIdio_safe_load_patch` `65e4f95`: declared `GPL-3.0` ✓
- `00_rAIdio_torchaudio_patch` `65e4f95`: declared `GPL-3.0` ✓
- `ComfyUI-ChordMidi` `65e4f95`: declared `Apache-2.0` ✓
- `ComfyUI-Demucs-AudioSeparator` `d864b78a2acb`: declared `MIT` ✓
- `ComfyUI-QwenTTS` `d8122a8ba835`: declared `GPL-3.0` ✓
- `ComfyUI-RVC` `5829db683954`: declared `MIT` ✓
- `ComfyUI_ACE-Step` `d4c2dc104a69`: declared `Apache-2.0` ✓
- `rAIdio_aimdo_reset` `65e4f95`: declared `GPL-3.0` ✓
- `rAIdio_nodes` `65e4f95`: declared `Apache-2.0` ✓
- `rAIdio_whisper_patch` `65e4f95`: declared `GPL-3.0` ✓
- `rAIdio_xl_patch` `65e4f95`: declared `GPL-3.0` ✓
- `zz_rAIdio_rvc_bool_fix` `65e4f95`: declared `GPL-3.0` ✓
- `zz_rAIdio_rvc_infer_audio_fix` `65e4f95`: declared `GPL-3.0` ✓
- `zz_rAIdio_rvc_loadaudio_alias` `65e4f95`: declared `GPL-3.0` ✓

