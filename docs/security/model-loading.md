# Model Loading Security

## Threat model

A user downloads a "voice model.pth" from Discord, HuggingFace,
weibo, or any place that hosts user-shared RVC voices. They drop it
into rAIdio's RVC voice folder. The next time they run a generation,
ComfyUI's RVC node calls `torch.load(file)` on the bytes. If the file
is a malicious pickle (a `.pth` is just a pickle stream), arbitrary
Python executes on the user's machine — the classic ML-supply-chain
RCE.

This is the highest-impact vector this codebase has. Defender will
not catch it (no x86 malware bytes), VirusTotal cannot meaningfully
analyse pickle payloads, the SBOM cannot vouch for a file we never
saw before, and the binary hash cannot help because the malicious
file *isn't ours* — it's a user-supplied input that gets passed to
a deserialiser we ship.

The defense is at the load site: don't deserialise pickles whose
contents indicate code-execution intent.

## Phase 2a — `00_rAIdio_safe_load_patch` (LIVE)

A monkey-patch package in
[`rAIdio-bot/rAIdio-nodes`](https://github.com/rAIdio-bot/rAIdio-nodes/tree/main/00_rAIdio_safe_load_patch)
shipped in the AI content depot. Same pattern as
`00_rAIdio_rvc_patch` and `00_rAIdio_torchaudio_patch` — wraps an
upstream function at custom-node import time, never modifies FOSS
source.

The `00_` filename prefix forces ComfyUI to load this BEFORE any
node that calls `torch.load` at import, so the rebind is in place
before the first call.

### Two-layer wrapper

1. **`weights_only=True` default.** PyTorch 2.6+ refuses to execute
   pickle opcodes like `__reduce__` when this flag is set. Our
   wrapper calls `kwargs.setdefault("weights_only", True)` so any
   `torch.load(path)` without an explicit `weights_only=False`
   becomes safe-by-default.

2. **`picklescan` defense-in-depth.** When `torch.load` is given a
   path, the wrapper runs `picklescan.scan_file_path` first and
   refuses if any of these globals appear in the pickle:

   ```
   os.system, os.popen, nt.system, posix.system,
   subprocess.{Popen,call,check_call,check_output,run},
   builtins.{eval,exec,compile,open,__import__},
   shutil.rmtree, pty.spawn, platform.popen
   ```

   Picklescan refusal happens BEFORE the deserialiser is invoked,
   so even a caller that explicitly passes `weights_only=False`
   (some legacy paths in custom nodes do this for full-module
   pickles) is still gated.

### What this covers

Every `torch.load` call in the bundled ComfyUI Python — 23 sites
across RVC, SeedVC, QwenTTS, ACE-Step, plus any future nodes —
gets the wrapper for free. The audit that informed this work is
in the chat record from the 2026-04-26 session; the load sites
themselves are not modified.

The user-selected RVC voice path (`vc/modules.py:get_vc()`
calling `torch.load(person)` on a user-controlled `sid`) is THE
attack surface in our threat model, and is closed by the same
patch that closes the bundled paths.

### What this does NOT cover

- **Files loaded via `pickle.load` directly** (not via `torch.load`).
  Audit found one such site in RVC's JIT export module
  (`rvc/infer/lib/jit/__init__.py:104`). Phase 2b sweep will gate
  it.
- **`numpy.load(..., allow_pickle=True)`.** No instances in our
  audit, but Phase 2b will add a separate wrapper.
- **Auto-conversion to safetensors.** Phase 2c. Diverges from
  upstream RVC's training-output format and is deferred until
  there's a strong reason.

## Phase 2b — full sweep (planned, not started)

- Audit + gate every `pickle.load` / `joblib.load` /
  `numpy.load(allow_pickle=True)` site in our patches.
- Add `fickling` as a second-opinion scanner alongside picklescan
  (the two have different rule sets; running both reduces false
  negatives).
- Add a Tauri frontend gate that runs picklescan on a file *before*
  it lands in the voice-models folder, so the user sees the
  rejection in the UI rather than at generation time.

## Phase 2c — convert-and-cache (deferred)

- On first load of a verified-clean `.pth`, convert to
  `.safetensors` and cache. Subsequent loads bypass pickle
  entirely.
- Diverges from upstream RVC's training-output format; not
  pursued until there's a clear user-experience win.

## Verification at release time

Per `RELEASE.md`, every build runs:

- `build.ps1` SBOM-drift gate — ensures `picklescan` and the new
  custom-node pin are committed.
- Manual smoke (`docs/manual-smoke.md`) — RVC voice generation
  works end-to-end with the patch active.

For an explicit security smoke (recommended on any RC that touches
the patch):

1. **Patch loaded**: `Documents\rAIdio.bot\raidio.log` contains
   `[rAIdio] torch.load patched: weights_only=True default + picklescan gate`
   on backend startup.
2. **Benign load works**: a normal voice generation succeeds; no
   regression.
3. **Malicious load rejected**: this script writes a
   `__reduce__ -> os.system` pickle and confirms `torch.load` rejects
   it. Run from inside the bundled Python:

   ```python
   import os, pickle, torch
   class Pwn:
       def __reduce__(self):
           return (os.system, ("echo PWNED",))
   with open("malicious.pkl", "wb") as f:
       pickle.dump(Pwn(), f)
   try:
       torch.load("malicious.pkl", weights_only=False)
       print("FAIL — load was not rejected!")
   except RuntimeError as e:
       if "rAIdio.safe_load" in str(e):
           print("OK — rejected by picklescan layer")
   ```

## Reporting a malicious model file

Found a `.pth` that should be flagged but our wrapper allows? Report
via [SECURITY.md](../../SECURITY.md). Include the file's sha256, the
URL it was downloaded from, and ideally the `picklescan` output
(`python -m picklescan.scanner --path <file>`).

We will update the `_DANGEROUS_GLOBALS` list in
`00_rAIdio_safe_load_patch` and ship the change in the next RC.
