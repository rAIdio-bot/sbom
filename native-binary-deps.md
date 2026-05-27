# Python packages shipping native .pyd binaries

Source: walk of `Backend/comfyui_portable/python_embeded/Lib/site-packages/`
Date: 2026-05-27

- Top-level packages with .pyd files: **58**
- Loose .pyd at site-packages root: 5
- Total .pyd files shipped: 752

Per Till's 2026-05-27 §1 note: "In such cases (.pyd files) you
should ensure that the corresponding source code is identified
and scanned." This list feeds the ScanCode integration (Track C).

| Package dir | SBOM name | Version | License | .pyd count |
|-------------|-----------|---------|---------|------------|
| `aiohttp` | aiohttp | `3.13.3` | Apache-2.0 AND MIT | 4 |
| `av` | av | `16.1.0` | BSD-3-Clause | 49 |
| `blis` | blis | `1.3.3` | BSD-3-Clause | 2 |
| `charset_normalizer` | charset-normalizer | `3.4.6` | MIT | 2 |
| `comfy_kitchen` | comfy-kitchen | `0.2.7` | Apache-2.0 | 1 |
| `contourpy` | contourpy | `1.3.3` | BSD-3-Clause | 1 |
| `ctranslate2` | ctranslate2 | `4.7.1` | MIT | 1 |
| `cv2` | _(not matched)_ | — | — | 1 |
| `cymem` | cymem | `2.0.13` | MIT | 1 |
| `Cython` | Cython | `3.2.4` | Apache-2.0 | 16 |
| `faiss` | _(not matched)_ | — | — | 2 |
| `fontTools` | fonttools | `4.62.1` | MIT | 6 |
| `frozenlist` | frozenlist | `1.8.0` | Apache-2.0 | 1 |
| `fugashi` | fugashi | `1.5.2` | MIT AND BSD-3-Clause | 1 |
| `greenlet` | greenlet | `3.3.1` | MIT AND Python-2.0 | 3 |
| `grpc` | _(not matched)_ | — | — | 1 |
| `hf_xet` | hf-xet | `1.2.0` | Apache-2.0 | 1 |
| `kiwisolver` | kiwisolver | `1.5.0` | BSD-3-Clause | 1 |
| `kornia_rs` | kornia_rs | `0.1.10` | Apache-2.0 | 1 |
| `markupsafe` | MarkupSafe | `3.0.2` | BSD-3-Clause | 1 |
| `matplotlib` | matplotlib | `3.10.8` | PSF-2.0 | 8 |
| `msgpack` | msgpack | `1.1.2` | Apache-2.0 | 1 |
| `multidict` | multidict | `6.7.1` | Apache-2.0 | 1 |
| `murmurhash` | murmurhash | `1.0.15` | MIT | 1 |
| `numba` | numba | `0.64.0` | BSD-3-Clause | 14 |
| `numpy` | numpy | `2.2.6` | BSD-3-Clause | 19 |
| `onnxruntime` | onnxruntime | `1.24.3` | MIT | 1 |
| `PIL` | _(not matched)_ | — | — | 8 |
| `preshed` | preshed | `3.0.12` | MIT | 3 |
| `propcache` | propcache | `0.4.1` | Apache-2.0 | 1 |
| `psutil` | psutil | `7.2.1` | BSD-3-Clause | 1 |
| `pydantic_core` | pydantic_core | `2.41.5` | MIT | 1 |
| `pygit2` | pygit2 | `1.19.1` | GPL-2.0-only WITH GCC-exception-2.0 | 2 |
| `pyworld` | pyworld | `0.3.5` | MIT | 1 |
| `regex` | regex | `2026.2.28` | Apache-2.0 AND CNRI-Python | 1 |
| `safetensors` | safetensors | `0.7.0` | Apache-2.0 | 1 |
| `scipy` | scipy | `1.17.1` | BSD-3-Clause | 109 |
| `sentencepiece` | sentencepiece | `0.2.1` | Apache-2.0 | 1 |
| `sklearn` | _(not matched)_ | — | — | 69 |
| `soxr` | soxr | `1.0.0` | LGPL-2.1-or-later | 1 |
| `spacy` | spacy | `3.8.11` | MIT | 46 |
| `sqlalchemy` | SQLAlchemy | `2.0.46` | MIT | 5 |
| `srsly` | srsly | `2.5.2` | MIT | 4 |
| `thinc` | thinc | `8.3.10` | MIT | 6 |
| `tiktoken` | tiktoken | `0.12.0` | MIT | 1 |
| `tokenizers` | tokenizers | `0.22.2` | Apache-2.0 | 1 |
| `torch` | torch | `2.10.0+cu128` | BSD-3-Clause | 1 |
| `torchaudio` | torchaudio | `2.10.0+cu128` | BSD-3-Clause | 4 |
| `torchcodec` | torchcodec | `0.11.0` | BSD-3-Clause | 5 |
| `torchvision` | torchvision | `0.25.0+cu128` | BSD-3-Clause | 2 |
| `tornado` | tornado | `6.5.5` | Apache-2.0 | 1 |
| `triton` | _(not matched)_ | — | — | 1 |
| `wrapt` | wrapt | `2.1.2` | BSD-3-Clause | 1 |
| `yaml` | _(not matched)_ | — | — | 1 |
| `yarl` | yarl | `1.22.0` | Apache-2.0 | 1 |
| `~-ipy` | _(not matched)_ | — | — | 109 |
| `~cipy` | _(not matched)_ | — | — | 109 |
| `~~ipy` | _(not matched)_ | — | — | 109 |

## Loose .pyd files at site-packages root

- `81d243bd2c585b0f4821__mypyc.cp312-win_amd64.pyd`
- `_cffi_backend.cp312-win_amd64.pyd`
- `lameenc.cp312-win_amd64.pyd`
- `mojimoji.cp312-win_amd64.pyd`
- `parselmouth.cp312-win_amd64.pyd`

## Unmatched to SBOM (10)

These directories ship .pyd files but no matching `pkg:pypi/*` component was found in `sbom.json`. Likely vendored sub-packages of another distribution, naming mismatches that need curation, or transitive deps we haven't catalogued.

- `PIL`
- `cv2`
- `faiss`
- `grpc`
- `sklearn`
- `triton`
- `yaml`
- `~-ipy`
- `~cipy`
- `~~ipy`
