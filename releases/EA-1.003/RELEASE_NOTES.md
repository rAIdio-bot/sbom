# rAIdio.bot EA-1.003

- **Tag:** `EA-1.003` (commit `02767a7`; branch `release/EA-1.003` off `release/EA-1.002`)
- **AppID / Depot:** 4600000 / 4600001 (**app-only** push)
- **Raw BuildID:** 23678426 (set live on `default` + `beta`)
- **Shipped exe:** `raidio-bot.exe` — 43,990,528 bytes — sha256 `cff924ef1d348baf6d3c36c60a8251c5c6415b6c4ae31c39eaca10e70f5da1b2`
- **Components:** 1010 (CycloneDX 1.x — `rAIdio.bot-EA-1.003.cdx.json`)
- Content depot (4600002) unchanged from EA-1.002.

## What shipped (app-only hotfix off EA-1.002)
1. **picklescan 1.0.4 installed at backend launch.** `00_rAIdio_safe_load_patch`'s
   `pickle.load`/`numpy.load` malware-scan gate was a silent no-op on clean installs —
   picklescan was declared in the SBOM and docs but never wired into any install
   mechanism, so raw `pickle.load` ran ungated. Now installed via the launcher's runtime
   pip step so the gate actually applies.
2. **ComfyUI-RVC first-launch import fix.** The launcher pre-registers RVC's import paths
   via a clean `.pth` before ComfyUI starts, so `import rvc` / `import infer` resolve on
   the first launch (voice conversion / training previously failed until a restart).
3. **Memory-cleaner node self-heal (app-carried).** Ships the corrected
   `comfyui_memescreamer_memory_cleaner` (drops the `unload_all_models()` call that
   KeyErrored on ACE-Step and froze 0 GB; now clears CUDA cache + GC + working-set trim,
   leaving model eviction to `/free`) via the **app depot**, self-healed into
   `custom_nodes` on launch — matching the proven doomscroll cleaner, no content re-push.

## Notes
- VirusTotal scans of the bundled binaries are not included here (the daily SBOM monitor
  picks them up post-push, as with EA-1.002).
- The `rAIdio-nodes` pin in `tools/generate_sbom.py` still points at the pre-fix cleaner
  SHA so the embedded + CycloneDX SBOMs stay consistent with the shipped exe; bump it at
  the next content/release cut for full accuracy.
