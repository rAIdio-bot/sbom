# ScanCode summary — rAIdio-nodes packages

First ScanCode integration pass. Scans the 13 packages in
`rAIdio-nodes` (the 11 GPL-3.0 patches + 2 Apache-2.0 utility
packages) for source-header license declarations.

Per Till Jaeger's 2026-05-27 §1 guidance: "there are usually false
positives. I recommend to look manually into unexpected findings
(e.g. copyleft licenses in a project under a permissive license)."

| Package | Declared | Files | Conflicts | No-license |
|---------|----------|-------|-----------|------------|
| `00_rAIdio_rvc_patch` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `00_rAIdio_safe_load_patch` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `00_rAIdio_torchaudio_patch` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `ComfyUI-ChordMidi` | `Apache-2.0` | 5 | ✓ 0 | 2 |
| `rAIdio_aimdo_reset` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `rAIdio_nodes` | `Apache-2.0` | 3 | ✓ 0 | 0 |
| `rAIdio_whisper_patch` | `GPL-3.0-only` | 3 | ⚠️ 2 | 0 |
| `rAIdio_xl_patch` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `zz_rAIdio_rvc_bool_fix` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `zz_rAIdio_rvc_infer_audio_fix` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `zz_rAIdio_rvc_loadaudio_alias` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `zz_rAIdio_rvc_train_dir_fix` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |
| `zz_rAIdio_rvc_train_quote_fix` | `GPL-3.0-only` | 3 | ✓ 0 | 0 |

**Totals:** 41 files scanned, 2 conflict flags, 2 no-license.

## Manual review of flagged conflicts

**`rAIdio_whisper_patch`** flagged 2 conflicts. Both are textbook
ScanCode false-positives, exactly the kind Till warned about:

- `LICENSE` detected as `GPL-3.0-only AND GPL-3.0-or-later`. The
  file is the canonical GPL-3.0 text. ScanCode picks up the
  recommendation paragraph at the end ("either version 3 of the
  License, or (at your option) any later version") as a separate
  GPL-3.0-or-later detection. The file is unambiguously GPL-3.0-only.
  **Verdict: false positive.**
- `README.md` detected as `(GPL-3.0-only OR
  LicenseRef-scancode-commercial-license) AND GPL-3.0-only`. The
  README's License section reads only "GPL-3.0 — applied to GPL-3.0
  licensed ComfyUI ecosystem." ScanCode's commercial-license-OR
  pattern is matching on a phrase that does not appear in the actual
  text. **Verdict: false positive.**

## Next steps

- Extend ScanCode coverage from the 13 rAIdio-nodes packages to the
  rest of the SBOM (Python deps + Rust crates), with priority on the
  58 packages in `native-binary-deps.md` (those ship .pyd files
  whose source must be scanned per Till's §1 .pyd note).
- Per-component reports live under `scancode-reports/`.
