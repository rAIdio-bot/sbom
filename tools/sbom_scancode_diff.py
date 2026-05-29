"""Aggregate ScanCode full-pass results and diff against sbom.json.

Reads JSON files produced by scancode-fullpass/_run_all.sh and produces
deviations.md — a per-component diff between the ScanCode-detected
license and the SBOM-declared license, with standard ScanCode-triage
false-positive patterns filtered out.

False-positive filters applied:
  - GPL "or any later version" recommendation paragraph (LICENSE files
    detected as `GPL-3.0-only AND GPL-3.0-or-later`)
  - Phantom commercial-OR matches (`(X OR LicenseRef-scancode-commercial-license)`)
  - License-expression equivalences: `MIT AND MIT` -> `MIT`, etc.

Usage:
  python tools/sbom_scancode_diff.py
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_PATH = REPO_ROOT / "sbom.json"
CURATION_PATH = REPO_ROOT / "tools" / "sbom_drift_curation.json"
SCANS_DIR = REPO_ROOT / "scancode-fullpass"
OUT_PATH = REPO_ROOT / "deviations.md"

# Map each scan bucket -> the SBOM purl prefix(es) its components belong to
BUCKET_PURL_PREFIXES = {
    "npm": ("pkg:npm/",),
    "nodes": ("pkg:generic/",),     # ComfyUI nodes are tagged pkg:generic
    "overrides": ("pkg:generic/",), # _python_embeded_overrides_*
    "rust": ("pkg:cargo/",),
    "python": ("pkg:pypi/",),
}

# Patterns that count as ACK even though the strings differ literally
FP_PATTERNS = [
    # GPL appendix's "or any later version" recommendation
    (re.compile(r"^GPL-3\.0-only AND GPL-3\.0-or-later$"), "GPL-3.0"),
    (re.compile(r"^GPL-2\.0-only AND GPL-2\.0-or-later$"), "GPL-2.0"),
    # Phantom commercial-OR
    (re.compile(r"^\((GPL-3\.0-only) OR LicenseRef-scancode-commercial-license\) AND GPL-3\.0-only$"), "GPL-3.0-only"),
    (re.compile(r"LicenseRef-scancode-commercial-license"), None),  # mark for re-strip
]

LICENSE_FILENAMES = {
    "license", "license.txt", "license.md", "license-mit", "license-apache",
    "license-2.0", "license-2.0.txt",
    "copying", "copying.txt", "copying.md",
    "notice", "notice.txt", "notice.md",
}


def collapse_redundant(expr: str) -> str:
    """Collapse trivially-redundant expressions like 'MIT AND MIT' -> 'MIT'."""
    if not expr:
        return expr
    parts = [p.strip() for p in expr.split(" AND ")]
    if len(parts) > 1 and len(set(p.lower() for p in parts)) == 1:
        return parts[0]
    return expr


def strip_commercial_or(expr: str) -> str:
    """Strip ScanCode's phantom commercial-license OR-disjuncts."""
    if "LicenseRef-scancode-commercial-license" not in expr:
        return expr
    # Remove patterns like "(X OR LicenseRef-scancode-commercial-license)"
    new = re.sub(
        r"\((\S+) OR LicenseRef-scancode-commercial-license\)",
        r"\1",
        expr,
    )
    new = re.sub(
        r"LicenseRef-scancode-commercial-license OR ",
        "",
        new,
    )
    new = re.sub(
        r" OR LicenseRef-scancode-commercial-license",
        "",
        new,
    )
    return collapse_redundant(new)


def strip_licenseref_internal(expr: str) -> str:
    """ScanCode emits LicenseRef-scancode-* identifiers for ambiguous matches
    (e.g. unknown-license-reference, public-domain, proprietary-license).
    These are internal classifications, not real SPDX licenses. When that's
    the ONLY thing detected, treat as no-detection."""
    if not expr:
        return expr
    if "LicenseRef-scancode-" not in expr:
        return expr
    # Drop bare LicenseRef-scancode-* identifiers from AND/OR groups
    parts = re.split(r" (AND|OR) ", expr)
    cleaned = []
    last_op = None
    for i, p in enumerate(parts):
        if p in ("AND", "OR"):
            last_op = p
            continue
        if "LicenseRef-scancode-" in p:
            continue
        if cleaned and last_op:
            cleaned.append(last_op)
        cleaned.append(p)
        last_op = None
    result = " ".join(cleaned).strip()
    return result if result else ""


def apply_fp_filters(expr: str) -> str:
    """Apply known false-positive filters; return the cleaned expression."""
    if not expr:
        return expr
    expr = strip_commercial_or(expr)
    expr = strip_licenseref_internal(expr)
    expr = collapse_redundant(expr)
    # GPL or-later appendix recommendation
    expr = re.sub(r"^GPL-3\.0-only AND GPL-3\.0-or-later$", "GPL-3.0-only", expr)
    expr = re.sub(r"^GPL-3\.0-or-later AND GPL-3\.0-only$", "GPL-3.0-only", expr)
    expr = re.sub(r"^GPL-2\.0-only AND GPL-2\.0-or-later$", "GPL-2.0-only", expr)
    return expr


# Deprecated -> canonical SPDX synonyms (SPDX List v3.10+ deprecated the bare
# IDs in favour of explicit -only/-or-later variants but the bare form is
# still in wide use in package metadata).
SPDX_SYNONYMS = {
    "gpl-3.0": "gpl-3.0-only",
    "gpl-2.0": "gpl-2.0-only",
    "lgpl-2.1": "lgpl-2.1-only",
    "lgpl-3.0": "lgpl-3.0-only",
    "agpl-3.0": "agpl-3.0-only",
}


def norm_spdx(s: Optional[str]) -> str:
    if not s:
        return ""
    base = s.strip().lower().replace("_", "-").replace(" ", "")
    return SPDX_SYNONYMS.get(base, base)


def load_sbom() -> dict[str, dict[str, dict]]:
    """Return {purl_prefix: {component_key: component_metadata}} so we can
    enforce that a Rust-bucket directory only matches a Rust-purl component
    (and not, e.g., a Python or NPM component with the same name)."""
    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    by_prefix: dict[str, dict[str, dict]] = defaultdict(dict)
    for c in sbom.get("components", []):
        name = c.get("name", "")
        version = c.get("version", "")
        purl = c.get("purl", "")
        if not purl:
            continue
        # Identify the purl prefix
        prefix = None
        for p in ("pkg:cargo/", "pkg:npm/", "pkg:pypi/", "pkg:generic/"):
            if purl.startswith(p):
                prefix = p
                break
        if not prefix:
            continue
        licenses = []
        for lic in c.get("licenses", []):
            l = lic.get("license", {}) or {}
            lid = l.get("id") or l.get("name") or lic.get("expression")
            if lid:
                licenses.append(lid)
        record = {
            "name": name,
            "version": version,
            "purl": purl,
            "declared": " AND ".join(licenses) if licenses else "(none)",
        }
        for key in {
            name.lower(),
            name.lower().replace("_", "-"),
            name.lower().replace("-", "_"),
        }:
            by_prefix[prefix].setdefault(key, record)
    return dict(by_prefix)


def aggregate_component(top_dir: str, files: list[dict]) -> dict:
    """Pick the dominant detected license expression for one top-level dir."""
    license_detections = Counter()
    license_file_detected: Optional[str] = None
    license_file_seen = False
    n_files = 0
    n_with_license = 0

    for f in files:
        if f.get("type") != "file":
            continue
        n_files += 1
        spdx = f.get("detected_license_expression_spdx") or ""
        if spdx:
            n_with_license += 1
            license_detections[apply_fp_filters(spdx)] += 1
        path = f.get("path", "")
        basename = path.rsplit("/", 1)[-1].lower()
        # Heavyweight: an actual LICENSE / COPYING file at the package root
        rel_in_pkg = path.split("/", 2)[-1] if "/" in path else basename
        if basename in LICENSE_FILENAMES and "/" not in rel_in_pkg:
            license_file_seen = True
            if spdx:
                license_file_detected = apply_fp_filters(spdx)

    # Dominant: prefer LICENSE-file detection if present, else most common file-level
    if license_file_detected:
        dominant = license_file_detected
    elif license_detections:
        dominant, _ = license_detections.most_common(1)[0]
    else:
        dominant = ""

    return {
        "top_dir": top_dir,
        "n_files": n_files,
        "n_with_license": n_with_license,
        "license_file_seen": license_file_seen,
        "license_file_detected": license_file_detected,
        "dominant": dominant,
        "all_detected": dict(license_detections),
    }


def process_scan(bucket: str, scan_path: Path) -> dict[str, dict]:
    """Stream-parse one scan JSON and return per-top-dir aggregation."""
    if not scan_path.exists():
        return {}
    data = json.loads(scan_path.read_text(encoding="utf-8"))
    by_top: dict[str, list[dict]] = defaultdict(list)
    for f in data.get("files", []):
        path = f.get("path", "")
        if not path:
            continue
        top = path.split("/", 1)[0]
        by_top[top].append(f)

    aggregated = {}
    for top, files in by_top.items():
        aggregated[top] = aggregate_component(top, files)
    return aggregated


def classify(declared: str, detected: str) -> tuple[str, str]:
    """ACK / MISMATCH / NO-DETECTION. detected is post-FP-filter."""
    if not detected:
        return ("NO-DETECTION", "no detectable license in source")
    nd = norm_spdx(declared)
    de = norm_spdx(detected)
    if nd == de:
        return ("ACK", f"declared={declared!r} matches detected={detected!r}")
    # Compatibility: dual / multi-licence declared, detected matches one alternative
    if " OR " in declared:
        for alt in declared.split(" OR "):
            if norm_spdx(alt.strip().strip("()")) == de:
                return ("ACK", f"detected {detected!r} is one of the declared alternatives in {declared!r}")
    if " AND " in declared:
        # If declared is composite and detected is in it, still notable
        terms = [t.strip().strip("()") for t in declared.split(" AND ")]
        if any(norm_spdx(t) == de for t in terms):
            return ("ACK", f"detected {detected!r} is one component of declared composite {declared!r}")
    return ("MISMATCH", f"declared={declared!r} vs detected={detected!r}")


def load_curation() -> dict:
    if not CURATION_PATH.exists():
        return {}
    raw = json.loads(CURATION_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main() -> int:
    sbom_by_prefix = load_sbom()
    curation = load_curation()
    n_records = sum(len(v) for v in sbom_by_prefix.values())
    print(f"Loaded {n_records} component records from sbom.json across "
          f"{len(sbom_by_prefix)} purl prefixes", flush=True)
    print(f"Loaded {len(curation)} curation overrides", flush=True)

    results: list[dict] = []
    unaccounted: list[dict] = []
    curated: list[dict] = []

    for bucket in ("npm", "nodes", "overrides", "rust", "python"):
        scan_path = SCANS_DIR / f"{bucket}.json"
        if not scan_path.exists():
            print(f"  SKIP {bucket}: no scan output at {scan_path}")
            continue
        print(f"  Processing {bucket} ({scan_path.stat().st_size:,} bytes)...", flush=True)
        per_dir = process_scan(bucket, scan_path)
        print(f"    {len(per_dir)} top-level dirs", flush=True)
        # Only look up components whose purl matches this bucket's prefix(es).
        # Prevents name-collision matches (e.g. npm's `semver` finding the
        # Rust crate `semver`).
        prefixes = BUCKET_PURL_PREFIXES.get(bucket, ())
        candidate_records: dict[str, dict] = {}
        for prefix in prefixes:
            candidate_records.update(sbom_by_prefix.get(prefix, {}))

        for top, agg in per_dir.items():
            key = top.lower().replace("_", "-")
            record = candidate_records.get(key) or candidate_records.get(top.lower())
            if not record:
                unaccounted.append({"bucket": bucket, **agg, "key": top})
                continue
            # Curation override
            ck = f"{record['name']}@{record['version']}"
            if ck in curation:
                curated.append({
                    "bucket": bucket,
                    "name": record["name"],
                    "version": record["version"],
                    "declared": record["declared"],
                    "detected": agg["dominant"],
                    "rationale": curation[ck].get("rationale", "(no rationale recorded)"),
                })
                continue
            verdict, detail = classify(record["declared"], agg["dominant"])
            results.append({
                "bucket": bucket,
                "name": record["name"],
                "version": record["version"],
                "declared": record["declared"],
                "detected": agg["dominant"],
                "license_file_seen": agg["license_file_seen"],
                "n_files": agg["n_files"],
                "verdict": verdict,
                "detail": detail,
            })

    counts = Counter(r["verdict"] for r in results)
    mismatches = [r for r in results if r["verdict"] == "MISMATCH"]
    no_detect = [r for r in results if r["verdict"] == "NO-DETECTION"]
    acks = [r for r in results if r["verdict"] == "ACK"]

    lines = []
    lines.append("# ScanCode full-pass deviations report")
    lines.append("")
    lines.append("Full ScanCode v32.5.0 scan over every shipped component bucket "
                 "(Rust crates, NPM packages, Python deps, ComfyUI nodes, "
                 "embedded-Python overrides). Detected per-component dominant "
                 "license expression compared against the SBOM-declared license. "
                 "Known-false-positive patterns are filtered automatically "
                 "(GPL appendix \"or any later "
                 "version\" recommendation; phantom commercial-OR disjuncts; "
                 "trivially-redundant AND-conjunctions).")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Components matched to SBOM: **{len(results) + len(curated)}**")
    for v in ("ACK", "MISMATCH", "NO-DETECTION"):
        lines.append(f"  - {v}: {counts.get(v, 0)}")
    lines.append(f"  - CURATED (operator-documented rationale): {len(curated)}")
    lines.append(f"- Unaccounted scanned dirs (in source tree but not in SBOM): **{len(unaccounted)}**")
    lines.append("")

    if curated:
        lines.append(f"## CURATED ({len(curated)})")
        lines.append("")
        lines.append("Operator-documented overrides in `tools/sbom_drift_curation.json`.")
        lines.append("ScanCode's detection differs from the declared license intentionally.")
        lines.append("")
        for c in sorted(curated, key=lambda x: x["name"]):
            lines.append(f"- `{c['name']}` `{c['version']}`: declared `{c['declared']}`, detected `{c['detected']}`")
            r = c["rationale"]
            if len(r) > 200:
                r = r[:200] + "..."
            lines.append(f"  - {r}")
        lines.append("")

    if mismatches:
        lines.append(f"## MISMATCH ({len(mismatches)})")
        lines.append("")
        lines.append("These warrant manual review. The detected license differs "
                     "from the declared license after the false-positive filters.")
        lines.append("")
        lines.append("| Bucket | Component | Version | Declared | Detected | LICENSE file | Files |")
        lines.append("|--------|-----------|---------|----------|----------|--------------|-------|")
        for r in sorted(mismatches, key=lambda x: (x["bucket"], x["name"])):
            lf = "✓" if r["license_file_seen"] else "—"
            lines.append(f"| {r['bucket']} | `{r['name']}` | `{r['version']}` | `{r['declared']}` | `{r['detected']}` | {lf} | {r['n_files']} |")
        lines.append("")

    if no_detect:
        lines.append(f"## NO-DETECTION ({len(no_detect)})")
        lines.append("")
        lines.append("ScanCode found no detectable license in any file. Most of "
                     "these are tiny packages where the license is declared in "
                     "metadata (Cargo.toml, package.json, METADATA) rather than "
                     "in a LICENSE file or per-file header. Sample:")
        lines.append("")
        for r in no_detect[:30]:
            lines.append(f"- `{r['name']}` `{r['version']}` (declared `{r['declared']}`, "
                         f"{r['n_files']} files, {r['bucket']})")
        if len(no_detect) > 30:
            lines.append(f"- ... and {len(no_detect) - 30} more")
        lines.append("")

    if unaccounted:
        lines.append(f"## Unaccounted ({len(unaccounted)})")
        lines.append("")
        lines.append("Directories present in a source tree but not matched to any "
                     "SBOM component. Common reasons: cargo cache holds extra "
                     "crates beyond Cargo.lock; npm transitive subdirs; Python "
                     "package import-name vs distribution-name mismatch (e.g. "
                     "`PIL` vs `Pillow`, `cv2` vs `opencv-python-headless`); "
                     "metadata `.dist-info` / `.egg-info` directories; pip "
                     "shadow-update `~`-prefixed directories.")
        lines.append("")
        # Skip noise dirs from the listing
        noise_prefixes = ("__pycache__", ".dist-info", ".egg-info", "~")
        clean_unacc = [u for u in unaccounted
                       if not any(u["key"].startswith(p) or u["key"].endswith(p) for p in noise_prefixes)]
        lines.append(f"- Total: {len(unaccounted)}")
        lines.append(f"- After noise-stripping: {len(clean_unacc)}")
        lines.append("")
        lines.append("Sample of substantive unaccounted dirs:")
        for u in clean_unacc[:30]:
            lines.append(f"- `{u['key']}` ({u['bucket']}, {u['n_files']} files, "
                         f"detected `{u['dominant'] or 'none'}`)")
        if len(clean_unacc) > 30:
            lines.append(f"- ... and {len(clean_unacc) - 30} more")
        lines.append("")

    lines.append("## ACK sample")
    lines.append("")
    lines.append(f"{len(acks)} components where the detected license matches the "
                 "declared license (after FP filters). Not enumerated in full; "
                 "first 25 for spot-checking:")
    lines.append("")
    for r in acks[:25]:
        lines.append(f"- `{r['name']}` `{r['version']}`: declared `{r['declared']}` ✓")
    lines.append("")

    OUT_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {OUT_PATH}")
    print(f"  ACK: {counts.get('ACK', 0)}")
    print(f"  MISMATCH: {counts.get('MISMATCH', 0)}")
    print(f"  NO-DETECTION: {counts.get('NO-DETECTION', 0)}")
    print(f"  Unaccounted: {len(unaccounted)}")
    return 0 if counts.get("MISMATCH", 0) == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
