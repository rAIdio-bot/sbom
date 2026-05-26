"""Audit AI Model component licenses against HuggingFace API.

Walks sbom.json for every component tagged raidio:category=AI Models,
fetches the HuggingFace API metadata at the pinned revision SHA, and
compares the upstream-declared license to what we recorded in the SBOM.

This tool reports — it does NOT modify sbom.json. Each component is
classified ACK / MISMATCH / UNKNOWN; the operator triages MISMATCH and
UNKNOWN entries by hand. Per feedback_license_authority.md, conflicts
between HF metadata and an upstream github LICENSE file resolve in
favour of the github LICENSE.

Usage:
    python tools/sbom_audit_weights.py

Output:
    Stdout report + audit-report-weights.txt at sbom repo root.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
SBOM_PATH = REPO_ROOT / "sbom.json"
CURATION_PATH = REPO_ROOT / "tools" / "sbom_drift_curation.json"
REPORT_PATH = REPO_ROOT / "audit-report-weights.txt"

HTTP_TIMEOUT_S = 30
USER_AGENT = "rAIdio-bot-sbom-audit/0.2 (+https://github.com/rAIdio-bot/sbom)"


def get_property(component: dict, name: str) -> Optional[str]:
    for prop in component.get("properties", []):
        if prop.get("name") == name:
            return prop.get("value")
    return None


def get_homepage(component: dict) -> Optional[str]:
    for ref in component.get("externalReferences", []):
        if ref.get("type") == "website":
            return ref.get("url")
    return None


def get_vcs(component: dict) -> Optional[str]:
    for ref in component.get("externalReferences", []):
        if ref.get("type") == "vcs":
            return ref.get("url")
    return None


def github_repo_id_from_url(url: Optional[str]) -> Optional[str]:
    if not url or "github.com/" not in url:
        return None
    tail = url.split("github.com/", 1)[1]
    tail = tail.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def fetch_github_license(repo_id: str) -> Optional[dict]:
    url = f"https://api.github.com/repos/{repo_id}/license"
    req = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_url": url}
    except urllib.error.URLError as e:
        return {"_error": f"URLError: {e.reason}", "_url": url}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}", "_url": url}


def github_declared_license(meta: dict) -> Optional[str]:
    if not meta or meta.get("_error"):
        return None
    lic = meta.get("license") or {}
    return lic.get("spdx_id") if isinstance(lic, dict) else None


def recorded_license(component: dict) -> str:
    parts: list[str] = []
    for lic in component.get("licenses", []):
        l = lic.get("license", {}) or {}
        lid = l.get("id") or l.get("name") or lic.get("expression")
        if lid:
            parts.append(lid)
    return " | ".join(parts) if parts else "(none)"


def hf_repo_id_from_url(url: str) -> Optional[str]:
    if not url or "huggingface.co/" not in url:
        return None
    tail = url.split("huggingface.co/", 1)[1]
    tail = tail.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def fetch_hf_metadata(repo_id: str, revision: str) -> Optional[dict]:
    url = f"https://huggingface.co/api/models/{repo_id}/revision/{revision}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}", "_url": url}
    except urllib.error.URLError as e:
        return {"_error": f"URLError: {e.reason}", "_url": url}
    except Exception as e:
        return {"_error": f"{type(e).__name__}: {e}", "_url": url}


def hf_declared_license(meta: dict) -> tuple[Optional[str], Optional[str]]:
    if not meta or meta.get("_error"):
        return None, None
    card = meta.get("cardData") or {}
    lic = card.get("license")
    if isinstance(lic, list):
        lic = " | ".join(str(x) for x in lic) if lic else None
    lic_name = card.get("license_name")
    return (lic if isinstance(lic, str) else None,
            lic_name if isinstance(lic_name, str) else None)


def normalise_for_compare(s: Optional[str]) -> str:
    if not s:
        return ""
    return s.strip().lower().replace("_", "-").replace(" ", "")


def classify(recorded: str, hf_license: Optional[str], hf_license_name: Optional[str], meta: Optional[dict]) -> tuple[str, str]:
    if meta is None or meta.get("_error"):
        err = meta.get("_error") if meta else "no metadata"
        return ("UNKNOWN", f"could not fetch HF metadata: {err}")
    if not hf_license and not hf_license_name:
        return ("UNKNOWN", "HF cardData carries no license/license_name field")
    n_recorded = normalise_for_compare(recorded)
    n_hf = normalise_for_compare(hf_license)
    n_hf_name = normalise_for_compare(hf_license_name)
    if n_recorded == n_hf or (n_hf_name and n_recorded == n_hf_name):
        return ("ACK", f"HF says license={hf_license!r}")
    if hf_license and "other" in n_hf and hf_license_name:
        return ("UNKNOWN",
                f"HF declared license=other, license_name={hf_license_name!r} — verify upstream")
    return ("MISMATCH",
            f"recorded={recorded!r} vs HF declared license={hf_license!r}"
            + (f" / license_name={hf_license_name!r}" if hf_license_name else ""))


def load_curation() -> dict:
    if not CURATION_PATH.exists():
        return {}
    raw = json.loads(CURATION_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main() -> int:
    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    curation = load_curation()

    weights: list[dict] = []
    for c in sbom.get("components", []):
        if get_property(c, "raidio:category") == "AI Models":
            weights.append(c)
    weights.sort(key=lambda c: c.get("name", "").lower())

    lines: list[str] = []
    lines.append("rAIdio.bot SBOM — AI Model weights license audit")
    lines.append(f"Components audited: {len(weights)}")
    lines.append("Method: per component, check (1) the upstream rights-holder's "
                 "HF publisher repo at HEAD, (2) the HF mirror at our pinned SHA, "
                 "(3) the github canonical LICENSE as a code-repo tiebreaker, "
                 "(4) sbom_drift_curation.json for documented overrides. The "
                 "rights-holder's own declaration controls for HF-only weight "
                 "artefacts; the github canonical-LICENSE rule applies only when "
                 "github actually hosts the artefact being licensed.")
    lines.append("")

    counts = {"ACK": 0, "MISMATCH": 0, "UNKNOWN": 0, "CURATED": 0}

    for c in weights:
        name = c.get("name", "?")
        version = c.get("version", "?")
        recorded = recorded_license(c)
        homepage = get_homepage(c) or ""
        vcs = get_vcs(c) or ""
        # mirror_repo_id is the HF mirror in homepage (our memescreamer mirror)
        mirror_repo_id = hf_repo_id_from_url(homepage)
        # upstream_hf_repo_id is the rights-holder's own HF (from vcs if HF, else None)
        upstream_hf_repo_id = hf_repo_id_from_url(vcs)
        # github fallback if vcs (or homepage) is a github URL
        gh_repo_id = github_repo_id_from_url(vcs) or github_repo_id_from_url(homepage)

        lines.append("─" * 75)
        lines.append(f"COMPONENT:   {name}")
        lines.append(f"PIN:         {version}")
        lines.append(f"RECORDED:    {recorded}")
        lines.append(f"HOMEPAGE:    {homepage}")
        if vcs:
            lines.append(f"VCS:         {vcs}")

        # 1. Documented curation override
        curation_key = f"{name}@{version}"
        if curation_key in curation:
            rationale = curation[curation_key].get("rationale", "(no rationale recorded)")
            counts["CURATED"] += 1
            lines.append(f"VERDICT:     CURATED")
            lines.append(f"DETAIL:      sbom_drift_curation.json: {rationale[:200]}"
                         + ("..." if len(rationale) > 200 else ""))
            continue

        verdict: Optional[str] = None
        detail: Optional[str] = None

        # 2. Upstream rights-holder's HF publisher (HEAD) — most authoritative for HF-only weights
        if upstream_hf_repo_id:
            up_meta = fetch_hf_metadata(upstream_hf_repo_id, "main")
            up_lic, up_lic_name = hf_declared_license(up_meta) if up_meta else (None, None)
            lines.append(f"UPSTREAM_HF: {upstream_hf_repo_id}")
            lines.append(f"UP_LICENSE:  {up_lic!r}")
            if up_lic and not (up_meta or {}).get("_error"):
                n_recorded = normalise_for_compare(recorded)
                n_up = normalise_for_compare(up_lic)
                if n_recorded == n_up:
                    verdict, detail = "ACK", f"upstream HF publisher declares {up_lic!r}"
                else:
                    verdict, detail = "MISMATCH", (
                        f"recorded={recorded!r} vs upstream HF publisher declares {up_lic!r}"
                    )

        # 3. HF mirror at pinned SHA
        if verdict is None and mirror_repo_id:
            mir_meta = fetch_hf_metadata(mirror_repo_id, version)
            mir_lic, mir_lic_name = hf_declared_license(mir_meta) if mir_meta else (None, None)
            lines.append(f"MIRROR_HF:   {mirror_repo_id}")
            lines.append(f"MIR_LICENSE: {mir_lic!r}")
            mir_verdict, mir_detail = classify(recorded, mir_lic, mir_lic_name, mir_meta)
            if mir_verdict == "ACK":
                verdict, detail = mir_verdict, f"HF mirror declares {mir_lic!r}"
            else:
                lines.append(f"MIR_VERDICT: {mir_verdict} ({mir_detail})")

        # 4. github canonical LICENSE — only applies if github hosts the artefact (code repos)
        if verdict is None and gh_repo_id:
            gh_meta = fetch_github_license(gh_repo_id)
            gh_spdx = github_declared_license(gh_meta)
            lines.append(f"GH_REPO:     {gh_repo_id}")
            lines.append(f"GH_SPDX:     {gh_spdx!r}")
            if gh_meta and gh_meta.get("_error"):
                verdict, detail = "UNKNOWN", f"github license API: {gh_meta['_error']}"
            elif not gh_spdx:
                verdict, detail = "UNKNOWN", "github license API returned no SPDX id"
            else:
                n_recorded = normalise_for_compare(recorded)
                n_gh = normalise_for_compare(gh_spdx)
                if n_recorded == n_gh:
                    verdict, detail = "ACK", f"github canonical LICENSE detected as {gh_spdx!r}"
                else:
                    verdict, detail = "MISMATCH", (
                        f"recorded={recorded!r} vs github canonical LICENSE detected as {gh_spdx!r}"
                    )

        if verdict is None:
            verdict, detail = "UNKNOWN", "no upstream HF, no mirror metadata, no usable github ref"

        counts[verdict] += 1
        lines.append(f"VERDICT:     {verdict}")
        lines.append(f"DETAIL:      {detail}")

    lines.append("─" * 75)
    lines.append("")
    lines.append("SUMMARY")
    for k in ("ACK", "MISMATCH", "UNKNOWN", "CURATED"):
        lines.append(f"  {k}: {counts[k]}")

    report = "\n".join(lines) + "\n"
    REPORT_PATH.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0 if counts["MISMATCH"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
