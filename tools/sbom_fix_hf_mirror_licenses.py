"""Set the `license:` field in every memescreamer HF mirror's model card.

The weights audit (tools/sbom_audit_weights.py) confirmed that all 20+
memescreamer HF mirrors have empty `cardData.license`, even though the
upstream github canonical LICENSE is unambiguous in every case. This tool
updates each mirror's model-card YAML frontmatter so the HF API and UI
correctly declare the license.

Authoritative source: upstream github canonical LICENSE (the rule from
feedback_license_authority.md). The mapping table below is built from
the GH_SPDX values in audit-report-weights.txt — verify against that
report before running live.

Usage:
    python tools/sbom_fix_hf_mirror_licenses.py --dry-run   # preview
    python tools/sbom_fix_hf_mirror_licenses.py             # live

This is a write to public memescreamer HF repos. Dry-run first.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from huggingface_hub import HfApi, metadata_update

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_PATH = REPO_ROOT / "sbom.json"

# HF license identifiers are SPDX-ish but lowercase.
SPDX_TO_HF = {
    "Apache-2.0": "apache-2.0",
    "MIT": "mit",
    "GPL-3.0": "gpl-3.0",
    "GPL-3.0-only": "gpl-3.0",
    "GPL-3.0-or-later": "gpl-3.0",
    "BSD-3-Clause": "bsd-3-clause",
    "BSD-2-Clause": "bsd-2-clause",
}


def get_property(component: dict, name: str):
    for prop in component.get("properties", []):
        if prop.get("name") == name:
            return prop.get("value")
    return None


def get_ref(component: dict, ref_type: str):
    for ref in component.get("externalReferences", []):
        if ref.get("type") == ref_type:
            return ref.get("url")
    return None


def hf_repo_id_from_url(url):
    if not url or "huggingface.co/" not in url:
        return None
    tail = url.split("huggingface.co/", 1)[1]
    tail = tail.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def recorded_license_spdx(component: dict):
    for lic in component.get("licenses", []):
        l = lic.get("license", {}) or {}
        lid = l.get("id") or l.get("name") or lic.get("expression")
        if lid:
            return lid
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = ap.parse_args()

    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    api = HfApi()

    # Deduplicate by HF repo (multiple SBOM components map to one repo).
    repos: dict[str, dict] = {}
    for c in sbom.get("components", []):
        if get_property(c, "raidio:category") != "AI Models":
            continue
        homepage = get_ref(c, "website") or ""
        repo_id = hf_repo_id_from_url(homepage)
        if not repo_id:
            continue
        recorded = recorded_license_spdx(c)
        if not recorded:
            continue
        hf_lic = SPDX_TO_HF.get(recorded)
        if not hf_lic:
            print(f"WARN: no HF mapping for SPDX {recorded!r} (component {c.get('name')})",
                  file=sys.stderr)
            continue
        existing = repos.get(repo_id)
        if existing and existing["license"] != hf_lic:
            print(f"WARN: conflicting licenses for {repo_id}: "
                  f"{existing['license']!r} vs {hf_lic!r} — skipping", file=sys.stderr)
            repos[repo_id]["conflict"] = True
            continue
        if not existing:
            repos[repo_id] = {
                "license": hf_lic,
                "spdx": recorded,
                "components": [c.get("name")],
            }
        else:
            existing["components"].append(c.get("name"))

    if args.dry_run:
        print("=== DRY RUN — no changes will be made ===\n")
    print(f"{'HF REPO':55s}  {'SPDX':14s}  {'HF VALUE':12s}  COMPONENTS")
    print("─" * 110)
    for repo_id, info in sorted(repos.items()):
        if info.get("conflict"):
            continue
        comps = ", ".join(info["components"])
        if len(comps) > 35:
            comps = comps[:32] + "..."
        print(f"{repo_id:55s}  {info['spdx']:14s}  {info['license']:12s}  {comps}")
    print(f"\nTotal HF mirror repos: {len(repos)}")

    if args.dry_run:
        print("\nNo HF API calls made. Re-run without --dry-run to write.")
        return 0

    print("\n=== LIVE — updating HF mirror model cards ===\n")
    n_ok = 0
    n_err = 0
    for repo_id, info in sorted(repos.items()):
        if info.get("conflict"):
            print(f"SKIP   {repo_id}: license conflict between mapped components")
            continue
        try:
            metadata_update(
                repo_id=repo_id,
                metadata={"license": info["license"]},
                repo_type="model",
                overwrite=False,
                create_pr=False,
                commit_message=f"set license: {info['license']} (per upstream canonical LICENSE)",
            )
            print(f"OK     {repo_id}: license = {info['license']}")
            n_ok += 1
        except Exception as e:
            print(f"ERROR  {repo_id}: {type(e).__name__}: {e}")
            n_err += 1

    print(f"\nResult: {n_ok} updated, {n_err} errors")
    return 0 if n_err == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
