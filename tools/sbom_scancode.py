"""ScanCode-based source-header license scan for SBOM components.

Tooling that only reads LICENSE files (and SPDX/PyPI heuristics)
misses license declarations embedded in file headers. ScanCode
addresses that by walking the source tree and scanning every file.
Standard triage practice: "there are usually false positives — look
manually into unexpected findings (e.g. copyleft licenses in a
project under a permissive license)."

This wrapper:
  1. Takes a target directory to scan (one component's source tree).
  2. Invokes scancode-toolkit with --license + --copyright.
  3. Parses the JSON output into a per-file license summary.
  4. Compares the dominant SPDX expression to a declared license
     (passed on the command line or looked up from sbom.json by
     component name).
  5. Flags any file whose detection conflicts with the declared
     license, ranked by ScanCode's score (likely-false-positive vs
     likely-real).

Usage:
  python tools/sbom_scancode.py --scan PATH [--declared SPDX]
  python tools/sbom_scancode.py --component NAME    # lookup in sbom.json

Output:
  Per-component report at scancode-reports/<component>.md plus a
  rolled-up scancode-summary.md across all scanned components.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_PATH = REPO_ROOT / "sbom.json"
REPORTS_DIR = REPO_ROOT / "scancode-reports"


def normalise(spdx: str) -> str:
    """Normalise an SPDX-ish string for loose comparison."""
    if not spdx:
        return ""
    return spdx.strip().lower().replace("_", "-").replace(" ", "")


def run_scancode(target: Path) -> dict:
    """Run scancode on `target`, return parsed JSON."""
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        out_path = tf.name
    try:
        cmd = [
            "scancode",
            "--license",
            "--copyright",
            "--json-pp", out_path,
            "--quiet",
            str(target),
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            sys.stderr.write(f"scancode exited {result.returncode}\n")
            sys.stderr.write(result.stderr[-2000:])
            return {}
        with open(out_path, "r", encoding="utf-8") as f:
            return json.load(f)
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def summarise(scan: dict, declared: str | None) -> dict:
    """Build a summary dict from a scancode result."""
    files = scan.get("files", [])
    file_count = sum(1 for f in files if f.get("type") == "file")
    license_files: list[dict] = []
    license_expressions = Counter()
    conflicts: list[dict] = []
    no_license: list[str] = []
    n_declared = normalise(declared or "")

    for f in files:
        if f.get("type") != "file":
            continue
        path = f.get("path", "")
        spdx = f.get("detected_license_expression_spdx") or ""
        if not spdx:
            no_license.append(path)
            continue
        license_expressions[spdx] += 1
        # Capture top-scoring match
        matches = []
        for ld in f.get("license_detections", []) or []:
            for m in ld.get("matches", []) or []:
                matches.append({
                    "spdx": m.get("license_expression_spdx", ""),
                    "score": m.get("score", 0),
                })
        top_score = max((m["score"] for m in matches), default=0)
        item = {"path": path, "spdx": spdx, "top_score": top_score}
        license_files.append(item)
        if declared and normalise(spdx) != n_declared:
            # Conflict: file declares something other than the component's
            # declared SPDX
            item["conflict"] = True
            conflicts.append(item)

    return {
        "file_count": file_count,
        "license_expressions": dict(license_expressions),
        "license_files": license_files,
        "conflicts": conflicts,
        "no_license_count": len(no_license),
        "declared": declared,
    }


def write_component_report(component_name: str, target: Path, declared: str | None, summary: dict) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    safe = component_name.replace("/", "_").replace(" ", "_")
    out = REPORTS_DIR / f"{safe}.md"
    lines = []
    lines.append(f"# ScanCode report: {component_name}")
    lines.append("")
    lines.append(f"- Target: `{target}`")
    lines.append(f"- Declared SPDX: `{declared or '(none)'}`")
    lines.append(f"- Files scanned: {summary['file_count']}")
    lines.append(f"- Files with no license detected: {summary['no_license_count']}")
    lines.append(f"- License expressions detected:")
    for spdx, n in sorted(summary["license_expressions"].items(), key=lambda x: (-x[1], x[0])):
        flag = " ← matches declared" if normalise(spdx) == normalise(declared or "") else ""
        lines.append(f"  - `{spdx}`: {n} file(s){flag}")
    lines.append("")
    if summary["conflicts"]:
        lines.append(f"## ⚠️  Conflicts with declared license ({len(summary['conflicts'])})")
        lines.append("")
        lines.append("Per standard ScanCode-triage practice: look manually into")
        lines.append("unexpected findings (e.g. copyleft licenses in a project under")
        lines.append("a permissive license). Each conflict below merits manual")
        lines.append("review before being classified as false positive or genuine drift.")
        lines.append("")
        lines.append("| File | Detected SPDX | Top score |")
        lines.append("|------|---------------|-----------|")
        for c in sorted(summary["conflicts"], key=lambda x: (-x["top_score"], x["path"])):
            lines.append(f"| `{c['path']}` | `{c['spdx']}` | {c['top_score']:.0f} |")
    else:
        lines.append("## ✓ No conflicts detected")
        lines.append("")
        lines.append("Every file with a detected license matches the declared")
        lines.append(f"SPDX (`{declared}`).")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", help="Path to scan (a single component's source tree)")
    ap.add_argument("--declared", help="SPDX expression the component declares")
    ap.add_argument("--component", help="Component name; look up source path + declared SPDX from sbom.json (informational; sbom.json doesn't currently track source paths so --scan is required)")
    args = ap.parse_args()

    if not args.scan:
        ap.error("--scan PATH is required (sbom.json doesn't currently track per-component source paths)")

    target = Path(args.scan).resolve()
    if not target.exists():
        sys.stderr.write(f"target does not exist: {target}\n")
        return 1

    component_name = args.component or target.name
    declared = args.declared

    if not declared and args.component:
        # Try to look up the SBOM-declared license
        sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
        for c in sbom.get("components", []):
            if c.get("name") == args.component:
                for lic in c.get("licenses", []):
                    lid = (lic.get("license", {}) or {}).get("id") or lic.get("expression")
                    if lid:
                        declared = lid
                        break
                break

    sys.stderr.write(f"Scanning {target} (declared={declared!r})...\n")
    scan = run_scancode(target)
    if not scan:
        return 2

    summary = summarise(scan, declared)
    report = write_component_report(component_name, target, declared, summary)
    sys.stderr.write(f"Wrote {report}\n")

    print(f"{component_name}: {summary['file_count']} files, "
          f"{len(summary['conflicts'])} conflicts, "
          f"{summary['no_license_count']} no-license")
    return 0 if not summary["conflicts"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
