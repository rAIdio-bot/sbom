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
REPORT_PATH = REPO_ROOT / "audit-report-weights.txt"

HTTP_TIMEOUT_S = 30
USER_AGENT = "rAIdio-bot-sbom-audit/0.1 (+https://github.com/rAIdio-bot/sbom)"


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


def main() -> int:
    sbom = json.loads(SBOM_PATH.read_text(encoding="utf-8"))

    weights: list[dict] = []
    for c in sbom.get("components", []):
        if get_property(c, "raidio:category") == "AI Models":
            weights.append(c)
    weights.sort(key=lambda c: c.get("name", "").lower())

    lines: list[str] = []
    lines.append("rAIdio.bot SBOM — AI Model weights license audit")
    lines.append(f"Components audited: {len(weights)}")
    lines.append("Method: HuggingFace API at the pinned revision SHA. "
                 "Reports ACK / MISMATCH / UNKNOWN per component.")
    lines.append("Upstream github LICENSE outweighs HF metadata in conflicts "
                 "(per feedback_license_authority.md). UNKNOWN / MISMATCH "
                 "items require manual triage.")
    lines.append("")

    counts = {"ACK": 0, "MISMATCH": 0, "UNKNOWN": 0}

    for c in weights:
        name = c.get("name", "?")
        version = c.get("version", "?")
        recorded = recorded_license(c)
        homepage = get_homepage(c) or ""
        vcs = get_vcs(c) or ""
        hf_repo_id = hf_repo_id_from_url(homepage)
        # vcs ref preferred for github; fall back to homepage if homepage is github
        gh_repo_id = github_repo_id_from_url(vcs) or github_repo_id_from_url(homepage)

        lines.append("─" * 75)
        lines.append(f"COMPONENT:   {name}")
        lines.append(f"PIN:         {version}")
        lines.append(f"RECORDED:    {recorded}")
        lines.append(f"HOMEPAGE:    {homepage}")
        if vcs:
            lines.append(f"VCS:         {vcs}")

        verdict: Optional[str] = None
        detail: Optional[str] = None

        if hf_repo_id:
            meta = fetch_hf_metadata(hf_repo_id, version)
            hf_lic, hf_lic_name = hf_declared_license(meta) if meta else (None, None)
            lines.append(f"HF_REPO:     {hf_repo_id}")
            lines.append(f"HF_LICENSE:  {hf_lic!r}")
            if hf_lic_name:
                lines.append(f"HF_LIC_NAME: {hf_lic_name!r}")
            hf_verdict, hf_detail = classify(recorded, hf_lic, hf_lic_name, meta)
            # ACK on HF is sufficient. UNKNOWN or MISMATCH → fall through to github.
            if hf_verdict == "ACK":
                verdict, detail = hf_verdict, hf_detail
            else:
                lines.append(f"HF_VERDICT:  {hf_verdict} ({hf_detail})")

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
            verdict, detail = "UNKNOWN", "no HF mirror metadata and no usable upstream github ref"

        counts[verdict] += 1
        lines.append(f"VERDICT:     {verdict}")
        lines.append(f"DETAIL:      {detail}")

    lines.append("─" * 75)
    lines.append("")
    lines.append("SUMMARY")
    for k in ("ACK", "MISMATCH", "UNKNOWN"):
        lines.append(f"  {k}: {counts[k]}")

    report = "\n".join(lines) + "\n"
    REPORT_PATH.write_text(report, encoding="utf-8")
    sys.stdout.write(report)
    return 0 if counts["MISMATCH"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
