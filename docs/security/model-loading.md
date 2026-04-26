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

## Phase 2a + 2b — `00_rAIdio_safe_load_patch` (LIVE)

A single monkey-patch package in
[`rAIdio-bot/rAIdio-nodes`](https://github.com/rAIdio-bot/rAIdio-nodes/tree/main/00_rAIdio_safe_load_patch)
shipped in the AI content depot. Same pattern as
`00_rAIdio_rvc_patch` and `00_rAIdio_torchaudio_patch` — wraps
upstream functions at custom-node import time, never modifies FOSS
source. The `00_` filename prefix forces ComfyUI to import the patch
BEFORE any node that touches the wrapped primitives.

### Three wrappers, one shared rule set

| Primitive | Layer 1 (kernel-level) | Layer 2 (picklescan gate) | Failure mode |
|-----------|------------------------|---------------------------|--------------|
| `torch.load` | `kwargs.setdefault("weights_only", True)` — PyTorch 2.6+ refuses `__reduce__` opcodes. | `scan_file_path` on path argument; refuse on dangerous globals. | Picklescan parse error → log warning, continue with `weights_only=True` (kernel still safe). |
| `pickle.load`, `pickle.loads` | (none — raw pickle has no kernel safety net) | `scan_file_path` for files-with-name; `scan_pickle_bytes(io.BytesIO(buf))` for `BytesIO` and for `pickle.loads`. | **Fail closed** — picklescan parse error raises `RuntimeError`, no deserialisation. |
| `numpy.load` | `kwargs.setdefault("allow_pickle", False)` — numpy refuses pickled arrays itself when False. | `scan_file_path` (`.npy`) or `scan_zip_bytes` (`.npz`) when caller insists on `allow_pickle=True`. | Picklescan parse error → log warning, let numpy proceed (allow_pickle handling unchanged). |

The shared dangerous-globals set, identical across all three
wrappers:

```
os.system, os.popen, nt.system, posix.system,
subprocess.{Popen,call,check_call,check_output,run},
builtins.{eval,exec,compile,open,__import__},
shutil.rmtree, pty.spawn, platform.popen
```

Refusal happens BEFORE the deserialiser is invoked, so callers that
explicitly opt into legacy modes (`weights_only=False` on torch.load,
`allow_pickle=True` on numpy.load, raw `pickle.load*` calls) are still
gated by the picklescan layer.

### What this covers

Every standard pickle deserialisation in the bundled ComfyUI Python:

- 23 `torch.load` sites across RVC, SeedVC, QwenTTS, ACE-Step
  (audit 2026-04-26).
- 1 `pickle.load` site at `rvc/infer/lib/jit/__init__.py:104`
  (RVC JIT export).
- Any future call site in any node — the wrappers apply globally.

The user-selected RVC voice path (`vc/modules.py:get_vc()` calling
`torch.load(person)` on a user-controlled `sid`) — **THE** attack
surface in our threat model — is closed.

### What this does NOT cover (Phase 2c, deferred)

- **Auto-conversion to safetensors.** Diverges from upstream RVC's
  training-output format; not pursued until a clear UX win.
- **Tauri frontend pre-drop gate.** The load-time wrapper IS the
  defense; a UI gate would be belt-and-braces. Useful but not urgent.
- **`fickling` as a second-opinion scanner.** Picklescan covers the
  declared threat model. fickling is more useful as a CI-time check
  on inbound model files than as a runtime gate.

## Verification at release time

Per `RELEASE.md`, every build runs:

- `build.ps1` SBOM-drift gate — ensures `picklescan` and the new
  custom-node pin are committed.
- Manual smoke (`docs/manual-smoke.md`) — RVC voice generation
  works end-to-end with the patch active.

For an explicit security smoke (recommended on any RC that touches
the patch):

1. **Patch loaded**: `Documents\rAIdio.bot\raidio.log` contains all
   three lines on backend startup:
   - `[rAIdio] torch.load patched: weights_only=True default + picklescan gate`
   - `[rAIdio] pickle.load/loads patched: picklescan gate (fail-closed)`
   - `[rAIdio] numpy.load patched: allow_pickle=False default + picklescan gate when allow_pickle=True`
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
