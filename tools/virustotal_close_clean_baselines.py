#!/usr/bin/env python3
"""One-shot cleanup: close tracker issues for baseline-clean binaries.

When the quiet-baseline policy lands, the existing tracker issues that
were opened under the old "tracker per (RC, binary) regardless of flag
count" rule are still open. This script walks tools/virustotal_state.json
and closes every issue whose recorded scan had:

  - empty `engines_flagged`
  - AND zero malicious + zero suspicious in `last_seen_stats`

After closing, the script removes the `issue_number` field from the
state entry so a future flag re-triggers tracker creation via the
poll script's "no issue_number on file" branch.

Issues with any flag (e.g. RC-1-Gold-0.32 raidio-bot.exe with
Microsoft Defender, or any raidio-bot.exe with Kaspersky/Trapmine
heuristics) stay open — those are real signals.

stdlib-only. Defaults to dry-run; pass --apply to actually close.

Usage:
    python tools/virustotal_close_clean_baselines.py            # dry-run
    python tools/virustotal_close_clean_baselines.py --apply    # do it
"""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys


CLOSE_COMMENT = (
    "Auto-closing zero-flag baseline tracker per quiet-baseline policy.\n"
    "\n"
    "Every engine on this scan returned `undetected` (or non-applicable).\n"
    "State is preserved in `tools/virustotal_state.json`; if a future poll\n"
    "discovers a flag on this binary, a fresh tracker will be opened then.\n"
    "\n"
    "See `tools/virustotal_poll.py` docstring for the policy rationale."
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--state",
        default="tools/virustotal_state.json",
        help="Path to virustotal_state.json (default: tools/virustotal_state.json)",
    )
    ap.add_argument(
        "--repo",
        default="rAIdio-bot/sbom",
        help="GitHub repo for gh issue close (default: rAIdio-bot/sbom)",
    )
    ap.add_argument(
        "--apply",
        action="store_true",
        help="Actually close issues + write state. Without this, dry-run only.",
    )
    args = ap.parse_args()

    state_path = pathlib.Path(args.state)
    if not state_path.exists():
        print(f"State file not found: {state_path}", file=sys.stderr)
        return 1

    state = json.loads(state_path.read_text(encoding="utf-8"))

    to_close: list[tuple[str, int]] = []
    kept: list[tuple[str, int, list[str]]] = []
    no_issue: list[str] = []

    for key, entry in state.items():
        issue_number = entry.get("issue_number")
        if not issue_number:
            no_issue.append(key)
            continue
        flagged = entry.get("engines_flagged") or []
        stats = entry.get("last_seen_stats") or {}
        malicious = stats.get("malicious", 0) or 0
        suspicious = stats.get("suspicious", 0) or 0
        if not flagged and malicious == 0 and suspicious == 0:
            to_close.append((key, issue_number))
        else:
            kept.append((key, issue_number, flagged))

    print(f"State entries: {len(state)}")
    print(f"  No issue_number (already absent): {len(no_issue)}")
    print(f"  Kept open (at least one flag):    {len(kept)}")
    print(f"  Would close (zero-flag baselines): {len(to_close)}")

    if kept:
        print("\nKept open:")
        for key, num, flagged in sorted(kept):
            flags_str = ", ".join(flagged) if flagged else "(stats-only flag)"
            print(f"  #{num:<4} {key:<48} [{flags_str}]")

    if to_close:
        print("\nWould close:")
        for key, num in sorted(to_close):
            print(f"  #{num:<4} {key}")

    if not args.apply:
        print("\nDry-run (no changes). Re-run with --apply to close + update state.")
        return 0

    if not to_close:
        print("\nNothing to close.")
        return 0

    print(f"\nClosing {len(to_close)} issues on {args.repo}...")
    closed = 0
    failed: list[tuple[str, int, str]] = []
    for key, num in to_close:
        try:
            subprocess.run(
                [
                    "gh", "issue", "close", str(num),
                    "--repo", args.repo,
                    "--comment", CLOSE_COMMENT,
                ],
                check=True, capture_output=True, text=True,
            )
            entry = state[key]
            entry.pop("issue_number", None)
            closed += 1
            print(f"  closed #{num} ({key})")
        except subprocess.CalledProcessError as e:
            failed.append((key, num, e.stderr.strip()))
            print(f"  FAILED #{num} ({key}): {e.stderr.strip()}", file=sys.stderr)

    if failed:
        print(f"\n{len(failed)} close failure(s) — state NOT written, please re-run.", file=sys.stderr)
        return 1

    state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\nClosed {closed} issue(s). Updated {state_path} ({len(to_close)} issue_number fields removed).")
    print("Commit + push:")
    print(f"  git add {state_path}")
    print(f'  git commit -m "vt-monitor: prune issue_number from {closed} zero-flag baselines"')
    print(f"  git push origin main")
    return 0


if __name__ == "__main__":
    sys.exit(main())
