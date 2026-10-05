"""Step 2 of the benchmark: run AgentShield on every collected PR.

    python bench/run.py dev       # writes bench/results_dev.json
    python bench/run.py test      # writes bench/results_test.json

Each PR gets a fresh Registry (empty cache), like a real CI run, and real
PyPI/npm lookups. Time is wall-clock for the whole scan, network included.
The repo's file list stands in for the checked-out repo (see collect.py).
"""

from __future__ import annotations

import csv
import json
import os
import statistics
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from agentshield.cli import scan  # noqa: E402  (path set up above)
from agentshield.config import Config  # noqa: E402
from agentshield.registry import Registry  # noqa: E402

DATA = os.path.join(HERE, "data")


def load_prs(which: str) -> list[dict]:
    with open(os.path.join(HERE, f"prs_{which}.csv"), newline="") as fh:
        return list(csv.DictReader(fh))


def diff_path(pr: dict) -> str:
    return os.path.join(DATA, "diffs", f"{pr['repo'].replace('/', '__')}__{pr['number']}.diff")


def repo_files(pr: dict) -> list[str] | None:
    path = os.path.join(DATA, "trees", pr["repo"].replace("/", "__") + ".txt")
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return fh.read().splitlines()


def main() -> int:
    which = sys.argv[1] if len(sys.argv) > 1 else "test"
    results = []
    for i, pr in enumerate(load_prs(which), 1):
        with open(diff_path(pr), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        files = repo_files(pr)
        start = time.perf_counter()
        findings, notes, scanned = scan(text, Config(), Registry(), repo_root="/nonexistent",
                                        repo_files=files if files is not None else [])
        seconds = time.perf_counter() - start
        start = time.perf_counter()
        scan(text, Config(), None, repo_root="/nonexistent", repo_files=files or [])
        offline_seconds = time.perf_counter() - start
        results.append({
            "id": pr["id"], "group": pr["group"], "url": pr["url"],
            "diff_lines": text.count("\n"), "files_scanned": scanned,
            "seconds": round(seconds, 3), "offline_seconds": round(offline_seconds, 4),
            "findings": [f.to_dict() for f in findings], "notes": notes,
        })
        print(f"[{i}] {pr['id']}: {len(findings)} finding(s), {seconds:.2f}s", file=sys.stderr)

    with open(os.path.join(HERE, f"results_{which}.json"), "w") as fh:
        json.dump(results, fh, indent=1)
    times = [r["seconds"] for r in results]
    print(f"{len(results)} PRs, {sum(len(r['findings']) for r in results)} findings, "
          f"median {statistics.median(times):.2f}s, max {max(times):.2f}s", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
