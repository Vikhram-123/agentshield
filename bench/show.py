"""Print each finding with the diff lines around it, for labeling.

    python bench/show.py test               # every unlabeled finding in the test set
    python bench/show.py test RULE_PREFIX   # e.g. "secret" or "risky.no-tests"
    python bench/show.py dev --all          # including labeled ones
"""

from __future__ import annotations

import csv
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from agentshield.diff import parse_diff  # noqa: E402

from run import diff_path, load_prs  # noqa: E402

CONTEXT = 4


def finding_key(pr_id: str, f: dict) -> str:
    return f"{pr_id}|{f['rule']}|{f['file']}|{f['line']}"


def load_labels() -> dict[str, dict]:
    path = os.path.join(HERE, "labels.csv")
    if not os.path.exists(path):
        return {}
    with open(path, newline="") as fh:
        return {row["key"]: row for row in csv.DictReader(fh)}


def main() -> int:
    args = sys.argv[1:]
    show_all = "--all" in args
    positional = [a for a in args if not a.startswith("--")]
    which = positional[0] if positional else "test"
    prefix = positional[1] if len(positional) > 1 else ""
    labels = load_labels()
    prs = {p["id"]: p for p in load_prs(which)}
    with open(os.path.join(HERE, f"results_{which}.json")) as fh:
        results = json.load(fh)
    for r in results:
        todo = [f for f in r["findings"] if f["rule"].startswith(prefix)
                and (show_all or not labels.get(finding_key(r["id"], f), {}).get("label"))]
        if not todo:
            continue
        with open(diff_path(prs[r["id"]]), encoding="utf-8", errors="replace") as fh:
            files = {f.path: f for f in parse_diff(fh.read())}
        for f in todo:
            print("=" * 100)
            print(f"{finding_key(r['id'], f)}   [{f['severity']}]")
            print(f"  {f['message'][:200]}")
            fd = files.get(f["file"])
            if fd and f["line"]:
                for a in fd.added:
                    if abs(a.number - f["line"]) <= CONTEXT:
                        mark = ">>" if a.number == f["line"] else "  "
                        print(f"  {mark}{a.number:5} +{a.text[:160]}")
                for rm in fd.removed:
                    if abs(rm.number - f["line"]) <= 1:
                        print(f"  --{rm.number:5} -{rm.text[:160]}")
            elif fd:
                print(f"  (file-level; {len(fd.added)} added, {len(fd.removed)} removed, "
                      f"deleted={fd.is_deleted}, new={fd.is_new})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
