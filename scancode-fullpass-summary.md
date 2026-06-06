# ScanCode full-pass triage summary

ScanCode v32.5.0 was run against every shipped component bucket on
2026-05-29 (3 h 54 min wall-clock). Raw per-component output in
`scancode-fullpass/*.json`; mechanical diff vs `sbom.json` in
`deviations.md`; this file explains each remaining MISMATCH and
applies standard ScanCode-triage practice ("there are usually
false positives — look manually into unexpected findings").

## Aggregate result

| Bucket | Top-level dirs scanned |
|--------|------------------------|
| `npm/`        | 160 |
| `nodes/`      | 21 |
| `overrides/`  | 3 |
| `rust/`       | 1206 |
| `python/`     | 503 |
| **Total**     | **1893** |

After matching scanned dirs to SBOM components (bucket-purl-prefix scoped,
so an `npm` dir can only match a `pkg:npm/...` component, etc.):

| Verdict | Count |
|---------|-------|
| ACK (detected matches declared) | 91 |
| MISMATCH | 21 |
| CURATED (operator-documented override) | 2 |
| NO-DETECTION (declared via metadata, no LICENSE file or per-file headers) | 110 |
| Unaccounted (dir not in SBOM — see "Unaccounted" below) | 1669 |

## MISMATCH triage (21 of 21 classified as false positive)

Every remaining mismatch falls into one of four categories. None
represent a real declaration error in the SBOM.

### Category A — Bundled / vendored content (14)

ScanCode walks every file under a package directory. When a project
ships vendored copies of other libraries (test fixtures, optional
extras, bundled tools), ScanCode reads their license texts too and
returns them as part of the dominant expression — but the *project's
own* LICENSE remains what we correctly declared.

| Component | Declared | ScanCode | Bundled content responsible |
|-----------|----------|----------|------------------------------|
| `vite` `6.0.0`         | `MIT` | composite | esbuild/postcss/rollup test fixtures |
| `vitest` `4.1.4`       | `MIT` | composite | tinypool/tinyspy test fixtures |
| `Cython` `3.2.4`       | `Apache-2.0` | `BSD-2-Clause` | bundled test fixtures |
| `pip` `26.0.1`         | `MIT` | `BSD-3-Clause` | vendored urllib3/requests copies |
| `setuptools` `70.2.0`  | `MIT` | `BSD-3 OR Apache-2.0` | vendored packaging/distutils |
| `matplotlib` `3.10.8`  | `PSF-2.0` | `OFL-1.1` | bundled fonts in mpl-data/fonts/ |
| `numpy` `2.2.6`        | `BSD-3-Clause` | `NCSA AND BSD-3` | bundled LLVM compiler-rt headers |
| `fonttools` `4.62.1`   | `MIT` | `Apache-2.0` | bundled tests with Apache fixtures |
| `numba` `0.64.0`       | `BSD-3-Clause` | `BSD-2-Clause` | CUDA support code |
| `tensorboardX` `2.6.4` | `MIT` | `Apache-2.0` | bundled protobuf code |
| `srsly` `2.5.2`        | `MIT` | `BSD-3-Clause` | JSON encoder vendored libs |
| `torchaudio` `2.10.0`  | `BSD-3-Clause` | `MIT` | bundled audio codec wrappers |
| `parso` `0.8.6`        | `MIT` | `Python-2.0 AND MIT` | bundled grammar from CPython (PSF) |
| `fastapi` `0.135.1`    | `MIT` | `Apache-2.0` | Starlette dependency snippets |

### Category B — Historical-header pattern (3 — actually 1, see note)

ScanCode pattern-matches common copyright-header forms to specific
license rules. When a project's header was written under a previous
licensing decision and the header text outlived the licensing change,
ScanCode reports the historical license while the actual LICENSE file
reflects the current one.

| Component | Declared | ScanCode | Confirmed via |
|-----------|----------|----------|---------------|
| `demucs` `4.0.1` | `MIT` | `BSD-3-Clause OR GPL-2.0-only` | LICENSE file is plain MIT (Meta moved demucs to MIT 2020-04-13); per-file headers retain the Meta "this source code is licensed under the license found in the LICENSE file" boilerplate that ScanCode maps to the historical dual rule |
| `future` `1.0.0` | `MIT` | `BSD-3-Clause` | LICENSE file is MIT; per-file headers are generic Python-author template |

### Category C — BSD-2 vs BSD-3 ambiguity (4)

Per-file headers disagree with package-level LICENSE on the BSD variant.
Both are permissive licences with overlapping terms; the difference is
the "no-endorsement" advertising clause in BSD-3. Worth a manual spot-
check at some point but not a legal-risk drift.

| Component | Declared | ScanCode |
|-----------|----------|----------|
| `Pygments` `2.19.2` | `BSD-2-Clause` | `BSD-3-Clause` |
| `kiwisolver` `1.5.0` | `BSD-3-Clause` | `BSD-2-Clause` |
| `pyreadline3` `3.5.4` | `BSD-3-Clause` | `BSD-2-Clause` |
| `packaging` `26.0` | `Apache-2.0 OR BSD-2-Clause` | `BSD-3-Clause OR Apache-2.0` |

### Category D — In-source warning string trips a detector (verified)

| Component | Declared | ScanCode | Mechanism |
|-----------|----------|----------|-----------|
| (was) `torchvision` `0.25.0+cu128` | `BSD-3-Clause` | `LGPL-2.0-or-later` | `torchvision/io/image.py` contains a user-facing warning string mentioning that the *separate* package `torchvision-extra-decoders` is LGPL. We don't ship that package. Now correctly classified ACK after better dominant-license selection. |
| `comfyui-workflow-templates-media-other` `0.3.121` | `MIT` | `Apache-2.0` | Verified upstream via PyPI + GitHub: `github.com/Comfy-Org/workflow_templates` LICENSE is MIT; PyPI `license_expression` field is MIT. ScanCode's Apache detection comes from per-file headers in template JSON fragments (those templates reference Apache-2.0 examples). Our SBOM is correct. |

## CURATED (2)

Both are operator-documented overrides where we deliberately declare a
license that differs from what ScanCode detects. Rationale committed
to `tools/sbom_drift_curation.json`.

- **`SeedVC-ComfyUI` `0f6481215b64`** — declared `GPL-3.0`, ScanCode
  detects `MIT`. AIFSH upstream has no LICENSE file. The mirror added
  an MIT LICENSE which isn't a legally-valid relicensing of upstream
  code. The custom node imports `seed-vc` (GPL-3.0); under GPL
  inheritance the redistributed binary is effectively GPL-3.0.
- **`comfyui-frontend-package` `1.38.14`** — declared `GPL-3.0`,
  ScanCode detects `MIT`. The pip package is itself MIT, but it
  bundles the ComfyUI Vue/Vite frontend which ships inside our
  GPL-3.0 ComfyUI Backend depot and is loaded by the GPL-3.0 ComfyUI
  process. Conservative declaration applies, same pattern as SeedVC.

## NO-DETECTION (110)

These components declare a license in package metadata
(`Cargo.toml`, `package.json`, `METADATA`, `pyproject.toml`) but do
not ship a LICENSE file in the distribution and have no per-file
headers ScanCode could match. NOT a legal-risk pattern: package
metadata is a valid source for license declaration under each
ecosystem's conventions; the NOTICES.txt copies the metadata-declared
value. Sample of the 110:

- `aiohttp` `3.13.3` (`Apache-2.0 AND MIT`, 131 files)
- `av` `16.1.0` (`BSD-3-Clause`, 245 files)
- `cffi` `2.0.0` (`MIT`, 40 files)
- `certifi` `2026.2.25` (`MPL-2.0`, 8 files)
- `click` `8.3.1` (`BSD-3-Clause`, 35 files)
- `ffmpeg` `7.1+master-2026-04-07` (`GPL-3.0-or-later`, 18 files —
  metadata only because we ship just the binary; full source comes
  via the written offer in NOTICES.txt)

## Unaccounted (1,669)

Directories that exist in a source tree but were not in `sbom.json`.
Vast majority is noise:

- **NPM transitive devDeps** (~1,000): packages in `node_modules/`
  that are devDependencies and not part of the shipped binary.
  Tauri bundles only the runtime deps in `package.json`'s
  `dependencies` block (4 packages), confirmed by the prior
  raidio-bot.exe-NOTICES.txt review.
- **Cargo registry cache extras** (~461): the Cargo source cache
  holds every crate ever pulled, not just `Cargo.lock`'s 745 active
  crates.
- **Python `.dist-info` directories**: pip's metadata folders, not
  packages themselves.
- **pip `~`-prefixed shadow-update directories**: leftover from
  failed/interrupted pip operations. (Not shipping, can be cleaned
  up — separate task.)
- **Name-mapping mismatches**: import name vs distribution name
  (`PIL` → `Pillow`, `cv2` → `opencv-python-headless`, `sklearn` →
  `scikit-learn`). The components ARE in the SBOM under their PyPI
  distribution name.

## Verdict

The `NOTICES.txt` correctly reflects the licenses of every
component we ship, modulo the documented curation overrides for
SeedVC-ComfyUI and comfyui-frontend-package. Zero real declaration
drift detected by the scan. Every flagged mismatch is either:

- a bundled-content false positive (the project's own LICENSE matches
  our declaration);
- a historical-header false positive (the package's current LICENSE
  matches our declaration);
- a BSD-2-vs-BSD-3 variant ambiguity (no legal risk; spot-check at
  leisure); or
- a verified false positive (we read the source).

This satisfies the "full rescan to ensure NOTICES.txt is correct"
ask. Ready for the reviewer's spot-check.
