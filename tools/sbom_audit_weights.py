"""Audit AI Model component licenses against the mirror's documented source.

For each component tagged raidio:category=AI Models, this tool determines
the *documented* upstream — the source from which we actually obtained the
weights — and compares the upstream-publisher's declared license to what
we record in the SBOM. Per the "we mirror our source's declaration"
principle, the source's own claim controls.

Source resolution order:

  1. sbom_drift_curation.json — explicit operator-curated override.
     CURATED verdict, no API calls.
  2. The memescreamer mirror's README frontmatter — every memescreamer
     mirror declares its upstream as "Mirror of <ORG>/<NAME>" in the README
     ("Upstream" row of the field table). The upstream's HEAD cardData
     license is the recorded-against truth.
  3. Fallback: the vcs externalReference in the SBOM. If it's a HuggingFace
     URL, fetch HEAD cardData. If it's a github URL, fetch the canonical
     LICENSE via the github license API (only meaningful when github
     actually hosts the artefact being licensed).

This tool reports — it does NOT modify sbom.json. ACK / MISMATCH /
UNKNOWN / CURATED per component.

Usage:
    python tools/sbom_audit_weights.py

Output:
    Stdout report + audit-report-weights.txt at sbom repo root.
"""

from __future__ import annotations

import json
import re
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
USER_AGENT = "rAIdio-bot-sbom-audit/0.3 (+https://github.com/rAIdio-bot/sbom)"


def get_property(c: dict, name: str) -> Optional[str]:
    for p in c.get("properties", []):
        if p.get("name") == name:
            return p.get("value")
    return None


def get_ref(c: dict, ref_type: str) -> Optional[str]:
    for r in c.get("externalReferences", []):
        if r.get("type") == ref_type:
            return r.get("url")
    return None


def http_get(url: str, accept: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    """Return (body, error). body is text; error is None on success."""
    headers = {"User-Agent": USER_AGENT}
    if accept:
        headers["Accept"] = accept
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_S) as resp:
            return resp.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except urllib.error.URLError as e:
        return None, f"URLError: {e.reason}"
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def hf_repo_id_from_url(url: Optional[str]) -> Optional[str]:
    if not url or "huggingface.co/" not in url:
        return None
    tail = url.split("huggingface.co/", 1)[1]
    tail = tail.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def github_repo_id_from_url(url: Optional[str]) -> Optional[str]:
    if not url or "github.com/" not in url:
        return None
    tail = url.split("github.com/", 1)[1]
    tail = tail.split("?", 1)[0].split("#", 1)[0].rstrip("/")
    parts = tail.split("/")
    if len(parts) < 2:
        return None
    return f"{parts[0]}/{parts[1]}"


def fetch_hf_meta(repo_id: str, revision: str = "main") -> tuple[Optional[dict], Optional[str]]:
    body, err = http_get(f"https://huggingface.co/api/models/{repo_id}/revision/{revision}")
    if err:
        return None, err
    try:
        return json.loads(body), None
    except Exception as e:
        return None, f"JSON parse: {e}"


def fetch_mirror_readme_upstream(mirror_repo_id: str) -> Optional[str]:
    """Parse the mirror's README to find the documented upstream HF repo id."""
    body, err = http_get(f"https://huggingface.co/{mirror_repo_id}/raw/main/README.md")
    if err or not body:
        return None
    # Look for: # Mirror of <ORG>/<NAME>
    m = re.search(r"#\s*Mirror of\s+([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)", body)
    if m:
        return m.group(1)
    # Backup: look at the | Upstream | [X](URL) | row
    m = re.search(r"\|\s*Upstream\s*\|\s*\[([^\]]+)\]", body)
    if m:
        return m.group(1)
    return None


def fetch_github_spdx(repo_id: str) -> tuple[Optional[str], Optional[str]]:
    body, err = http_get(
        f"https://api.github.com/repos/{repo_id}/license",
        accept="application/vnd.github+json",
    )
    if err:
        return None, err
    try:
        meta = json.loads(body)
    except Exception as e:
        return None, f"JSON parse: {e}"
    lic = meta.get("license") or {}
    spdx = lic.get("spdx_id") if isinstance(lic, dict) else None
    return spdx, None


def recorded_license(c: dict) -> str:
    parts = []
    for lic in c.get("licenses", []):
        l = lic.get("license", {}) or {}
        lid = l.get("id") or l.get("name") or lic.get("expression")
        if lid:
            parts.append(lid)
    return " | ".join(parts) if parts else "(none)"


def hf_cardData_license(meta: dict) -> tuple[Optional[str], Optional[str]]:
    if not meta:
        return None, None
    card = meta.get("cardData") or {}
    lic = card.get("license")
    if isinstance(lic, list):
        lic = " | ".join(str(x) for x in lic) if lic else None
    ln = card.get("license_name")
    return (lic if isinstance(lic, str) else None,
            ln if isinstance(ln, str) else None)


def norm(s: Optional[str]) -> str:
    if not s:
        return ""
    return s.strip().lower().replace("_", "-").replace(" ", "")


def load_curation() -> dict:
    if not CURATION_PATH.exists():
        return {}
    raw = json.loads(CURATION_PATH.read_text(encoding="utf-8"))
    return {k: v for k, v in raw.items() if not k.startswith("_")}


def main() -> int:
    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))
    curation = load_curation()

    weights = [c for c in sbom.get("components", []) if get_property(c, "raidio:category") == "AI Models"]
    weights.sort(key=lambda c: c.get("name", "").lower())

    out: list[str] = [
        "rAIdio.bot SBOM — AI Model weights license audit",
        f"Components audited: {len(weights)}",
        "Method: we mirror our source's declaration. For each component,",
        "resolve the documented upstream from the mirror's README ('Mirror of",
        "X' header) or the SBOM's vcs externalReference, then fetch that",
        "upstream's HEAD HF cardData.license (or github canonical LICENSE if",
        "the upstream is a github URL). Compare to the recorded license.",
        "sbom_drift_curation.json entries are respected as documented",
        "operator overrides.",
        "",
    ]

    counts = {"ACK": 0, "MISMATCH": 0, "UNKNOWN": 0, "CURATED": 0}

    for c in weights:
        name = c.get("name", "?")
        version = c.get("version", "?")
        recorded = recorded_license(c)
        homepage = get_ref(c, "website") or ""
        vcs = get_ref(c, "vcs") or ""

        out.append("─" * 75)
        out.append(f"COMPONENT:   {name}")
        out.append(f"PIN:         {version}")
        out.append(f"RECORDED:    {recorded}")
        out.append(f"HOMEPAGE:    {homepage}")
        if vcs:
            out.append(f"VCS:         {vcs}")

        ck = f"{name}@{version}"
        if ck in curation:
            r = curation[ck].get("rationale", "(no rationale)")
            out.append("VERDICT:     CURATED")
            out.append(f"DETAIL:      sbom_drift_curation.json: " + (r[:200] + ("..." if len(r) > 200 else "")))
            counts["CURATED"] += 1
            continue

        verdict: Optional[str] = None
        detail: Optional[str] = None

        # Resolve documented upstream
        mirror_repo_id = hf_repo_id_from_url(homepage)
        doc_upstream_repo_id = None
        if mirror_repo_id:
            doc_upstream_repo_id = fetch_mirror_readme_upstream(mirror_repo_id)
            if doc_upstream_repo_id:
                out.append(f"MIRROR_REPO: {mirror_repo_id}")
                out.append(f"DOC_UPSTREAM:{doc_upstream_repo_id}  (from mirror README)")

        if not doc_upstream_repo_id and vcs:
            # Fall back to vcs ref — could be HF or github
            doc_upstream_repo_id_hf = hf_repo_id_from_url(vcs)
            if doc_upstream_repo_id_hf:
                doc_upstream_repo_id = doc_upstream_repo_id_hf
                out.append(f"DOC_UPSTREAM:{doc_upstream_repo_id}  (from vcs ref)")

        # 1. Try HF upstream HEAD cardData
        if doc_upstream_repo_id:
            up_meta, up_err = fetch_hf_meta(doc_upstream_repo_id, "main")
            if up_meta:
                up_lic, up_ln = hf_cardData_license(up_meta)
                out.append(f"UP_LICENSE:  {up_lic!r}" + (f" / license_name={up_ln!r}" if up_ln else ""))
                if up_lic:
                    if norm(recorded) == norm(up_lic):
                        verdict, detail = "ACK", f"upstream HF publisher declares {up_lic!r}"
                    else:
                        verdict, detail = "MISMATCH", f"recorded={recorded!r} vs upstream declares {up_lic!r}"
                else:
                    out.append(f"             (upstream HF cardData has no license field)")
            else:
                out.append(f"UP_FETCH_ERR:{up_err}")

        # 2. Github fallback if vcs is a github URL and no verdict yet
        if verdict is None:
            gh_repo_id = github_repo_id_from_url(vcs) or github_repo_id_from_url(homepage)
            if gh_repo_id:
                gh_spdx, gh_err = fetch_github_spdx(gh_repo_id)
                out.append(f"GH_REPO:     {gh_repo_id}")
                out.append(f"GH_SPDX:     {gh_spdx!r}")
                if gh_err:
                    verdict, detail = "UNKNOWN", f"github license API: {gh_err}"
                elif not gh_spdx:
                    verdict, detail = "UNKNOWN", "github license API returned no SPDX id"
                else:
                    if norm(recorded) == norm(gh_spdx):
                        verdict, detail = "ACK", f"github canonical LICENSE = {gh_spdx!r}"
                    else:
                        verdict, detail = "MISMATCH", f"recorded={recorded!r} vs github LICENSE = {gh_spdx!r}"

        if verdict is None:
            verdict, detail = "UNKNOWN", "no documented upstream and no usable fallback"

        counts[verdict] += 1
        out.append(f"VERDICT:     {verdict}")
        out.append(f"DETAIL:      {detail}")

    out.append("─" * 75)
    out.append("")
    out.append("SUMMARY")
    for k in ("ACK", "MISMATCH", "UNKNOWN", "CURATED"):
        out.append(f"  {k}: {counts[k]}")

    report = "\n".join(out) + "\n"
    REPORT_PATH.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0 if counts["MISMATCH"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
