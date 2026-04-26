#!/usr/bin/env python3
"""Poll VirusTotal for every release the SBOM repo tracks.

Runs daily from .github/workflows/virustotal_monitor.yml.

Reads the per-RC virustotal.json files written by push.ps1 (Step 5 in
the source repo), fetches the current scan state from VT, compares
against tools/virustotal_state.json, and emits a decisions JSON the
workflow consumes to open / comment / escalate GitHub issues.

Tier rules (single-maintainer policy — change MAINTAINERS / MENTION
below to add co-maintainers):

  baseline   First time we see this RC. Create issue, no email.
  silent     Stats unchanged. No-op (state timestamp updated only).
  minor      malicious+suspicious ticked up by 1, no major/Defender hit.
             Comment on the existing issue. No email.
  alert      malicious+suspicious >= 3. Escalate (label + assign + mention).
             Email lands.
  major      ESET / Kaspersky / BitDefender / Sophos / F-Secure flag.
             Escalate. Email lands.
  defender   Microsoft Defender flag. Escalate with priority/critical.
             Email lands.

stdlib-only — runs in actions/setup-python without `pip install`.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request

VT_BASE = "https://www.virustotal.com/api/v3"

# Single maintainer for now. Adding a co-maintainer = append to MAINTAINERS
# (assigned by GitHub) and append to MENTION (string literally interpolated
# into the issue body, GitHub mails on @-mention regardless of watch settings).
MAINTAINERS = ["neitzert"]
MENTION = "@neitzert"

DEFENDER_ENGINES = {"Microsoft"}
MAJOR_ENGINES = {
    "ESET-NOD32",
    "Kaspersky",
    "BitDefender",
    "BitDefenderTheta",
    "Sophos",
    "F-Secure",
    "FireEye",
    "Avast",
    "AVG",
}


def vt_get_file(sha256, api_key):
    req = urllib.request.Request(
        f"{VT_BASE}/files/{sha256}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))["data"]


def flagged_engines(results):
    """Return dict of engine -> verdict for engines reporting malicious/suspicious."""
    flags = {}
    for engine, r in (results or {}).items():
        if r.get("category") in ("malicious", "suspicious"):
            flags[engine] = r.get("result") or r.get("category")
    return flags


def compute_tier(stats, flags):
    """Return one of: silent | minor | alert | major | defender."""
    bad = (stats.get("malicious", 0) or 0) + (stats.get("suspicious", 0) or 0)
    flagged_set = set(flags.keys())
    if flagged_set & DEFENDER_ENGINES:
        return "defender"
    if flagged_set & MAJOR_ENGINES:
        return "major"
    if bad >= 3:
        return "alert"
    if bad >= 1:
        return "minor"
    return "silent"


def stats_unchanged(prior, current):
    keys = ("malicious", "suspicious", "harmless", "undetected")
    return all((prior.get(k) or 0) == (current.get(k) or 0) for k in keys)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def render_body(tag, sha256, vt_link, stats, flags, header):
    bad = (stats.get("malicious", 0) or 0) + (stats.get("suspicious", 0) or 0)
    lines = [
        header,
        "",
        f"- Tag: `{tag}`",
        f"- sha256: `{sha256}`",
        f"- VT report: {vt_link}",
        f"- malicious: {stats.get('malicious', 0)}, suspicious: {stats.get('suspicious', 0)}, undetected: {stats.get('undetected', 0)}, harmless: {stats.get('harmless', 0)}",
    ]
    if flags:
        lines.append("")
        lines.append("Engines flagging:")
        for engine, verdict in sorted(flags.items()):
            lines.append(f"- **{engine}**: {verdict}")
    if bad >= 1:
        lines.append("")
        lines.append(
            "Reminder: GPU-heavy ML applications occasionally false-positive on "
            "heuristic engines. A flag is not by itself proof of compromise — "
            "cross-check with the published sha256 in `SHA256SUMS` and the C2PA "
            "binary manifest (when available)."
        )
    return "\n".join(lines)


def collect_releases(releases_dir):
    """Return list of dicts loaded from each releases/<tag>/virustotal_*.json.

    Each release directory may contain multiple virustotal_*.json files
    (one per native binary scanned at release time — raidio-bot.exe,
    python.exe, ffmpeg.exe, etc.). The poll script tracks each (tag,
    filename) pair independently.
    """
    out = []
    for entry in sorted(pathlib.Path(releases_dir).iterdir()):
        if not entry.is_dir():
            continue
        for vt_path in sorted(entry.glob("virustotal_*.json")):
            with open(vt_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Defence-in-depth: older artefacts (pre-multi-binary) may not have
            # `filename` set. Derive from the file path stem in that case.
            if not data.get("filename"):
                data["filename"] = vt_path.stem.replace("virustotal_", "", 1)
            out.append(data)
    return out


def state_key(tag, filename):
    return f"{tag}/{filename}"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--releases-dir", default="releases")
    p.add_argument("--state", default="tools/virustotal_state.json")
    p.add_argument("--decisions-out", required=True)
    args = p.parse_args()

    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        print("VIRUSTOTAL_API_KEY not set", file=sys.stderr)
        sys.exit(2)

    state_path = pathlib.Path(args.state)
    state = {}
    if state_path.exists():
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)

    decisions = []
    releases = collect_releases(args.releases_dir)
    print(f"Polling {len(releases)} (tag, filename) pair(s)", file=sys.stderr)

    for rel in releases:
        tag = rel["tag"]
        filename = rel["filename"]
        sha256 = rel["sha256"]
        vt_link = rel.get("vt_link") or f"https://www.virustotal.com/gui/file/{sha256}"
        key = state_key(tag, filename)
        label = f"{tag} / {filename}"

        try:
            file_data = vt_get_file(sha256, api_key)
        except urllib.error.HTTPError as e:
            print(f"  {label}: VT GET failed ({e.code}); skipping", file=sys.stderr)
            continue

        attrs = file_data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        results = attrs.get("last_analysis_results", {}) or {}
        flags = flagged_engines(results)

        prior = state.get(key)
        if prior is None:
            tier = compute_tier(stats, flags)
            body = render_body(
                label,
                sha256,
                vt_link,
                stats,
                flags,
                "Baseline VirusTotal scan recorded for this binary.",
            )
            labels = ["vt-baseline"]
            if tier in ("alert", "major", "defender"):
                # If the very first scan is already bad, escalate immediately.
                labels.append(f"vt-{tier}")
                if tier == "defender":
                    labels.append("priority/critical")
                body = body + f"\n\n{MENTION} — first scan already in tier `{tier}`."
                decisions.append(
                    {
                        "kind": "create_issue",
                        "key": key,
                        "title": f"VirusTotal: {label} — scan tracker",
                        "body": body,
                        "labels": labels,
                        "assignees": MAINTAINERS,
                    }
                )
            else:
                decisions.append(
                    {
                        "kind": "create_issue",
                        "key": key,
                        "title": f"VirusTotal: {label} — scan tracker",
                        "body": body,
                        "labels": labels,
                        "assignees": [],
                    }
                )
            state[key] = {
                "tag": tag,
                "filename": filename,
                "sha256": sha256,
                "vt_link": vt_link,
                "last_seen_stats": stats,
                "engines_flagged": sorted(flags.keys()),
                "tier": tier,
                "last_polled": now_iso(),
            }
            continue

        # Existing tracker — diff against prior.
        if stats_unchanged(prior.get("last_seen_stats", {}), stats):
            prior["last_polled"] = now_iso()
            continue

        new_flags = {e: v for e, v in flags.items() if e not in (prior.get("engines_flagged") or [])}
        tier = compute_tier(stats, flags)
        prior_tier = prior.get("tier", "silent")

        comment_body = render_body(
            label,
            sha256,
            vt_link,
            stats,
            flags,
            f"VirusTotal scan changed (tier `{prior_tier}` -> `{tier}`).",
        )
        if new_flags:
            comment_body += "\n\nNew engines flagging since last poll:\n"
            for engine, verdict in sorted(new_flags.items()):
                comment_body += f"- **{engine}**: {verdict}\n"

        if prior.get("issue_number"):
            decision = {
                "kind": "comment",
                "key": key,
                "issue_number": prior["issue_number"],
                "body": comment_body,
            }
            # Escalate if tier crossed into the alert band and wasn't there before.
            escalation_tiers = {"alert", "major", "defender"}
            if tier in escalation_tiers and prior_tier not in escalation_tiers:
                decision["kind"] = "escalate"
                decision["labels_add"] = [f"vt-{tier}"]
                if tier == "defender":
                    decision["labels_add"].append("priority/critical")
                decision["assignees"] = MAINTAINERS
                decision["body"] = decision["body"] + f"\n\n{MENTION}"
            decisions.append(decision)
        else:
            # Lost the issue number somehow — recreate.
            decisions.append(
                {
                    "kind": "create_issue",
                    "key": key,
                    "title": f"VirusTotal: {label} — scan tracker",
                    "body": comment_body,
                    "labels": [f"vt-{tier}"] if tier != "silent" else ["vt-baseline"],
                    "assignees": MAINTAINERS if tier in ("alert", "major", "defender") else [],
                }
            )

        prior["last_seen_stats"] = stats
        prior["engines_flagged"] = sorted(flags.keys())
        prior["tier"] = tier
        prior["last_polled"] = now_iso()

    state_path.parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2, sort_keys=True)
        f.write("\n")
    with open(args.decisions_out, "w", encoding="utf-8") as f:
        json.dump(decisions, f, indent=2)
    print(f"Wrote {args.state}; {len(decisions)} decision(s) -> {args.decisions_out}", file=sys.stderr)


if __name__ == "__main__":
    main()
