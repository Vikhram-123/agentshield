"""Step 4 of the benchmark: turn results + labels into numbers.

    python bench/report.py --init-labels   # add unlabeled findings to labels.csv
    python bench/report.py                 # write bench/RESULTS.md

The headline numbers come from the held-out "test" set. The "dev" set is
reported too (before and after the fixes it led to), clearly marked as
optimistic, because the tool was tuned on it.

Precision = TP / (TP + FP) over labeled findings. With small counts a single
percentage overstates certainty, so each comes with a 95% Wilson interval.
"""

from __future__ import annotations

import csv
import json
import math
import os
import statistics
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from show import finding_key, load_labels  # noqa: E402

LABEL_FIELDS = ["key", "pr", "rule", "severity", "file", "line", "label", "reason"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% confidence interval for a proportion k/n (Wilson score interval).

    Better than p ± 1.96·sqrt(p(1-p)/n) for small n or p near 0/1, where
    that simple formula can give intervals below 0% or above 100%.
    """
    if n == 0:
        return 0.0, 1.0
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def rate(k: int, n: int) -> str:
    if n == 0:
        return "-"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {pct(k / n)} (95% CI {pct(lo)}-{pct(hi)})"


def load_json(name: str):
    path = os.path.join(HERE, name)
    if not os.path.exists(path):
        return None
    with open(path) as fh:
        return json.load(fh)


def init_labels() -> int:
    labels = load_labels()
    added = 0
    for name in ("results_dev.json", "results_test.json", "dev/results_before.json"):
        for r in load_json(name) or []:
            for f in r["findings"]:
                key = finding_key(r["id"], f)
                if key not in labels:
                    labels[key] = {"key": key, "pr": r["id"], "rule": f["rule"],
                                   "severity": f["severity"], "file": f["file"],
                                   "line": f["line"], "label": "", "reason": ""}
                    added += 1
    with open(os.path.join(HERE, "labels.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=LABEL_FIELDS)
        w.writeheader()
        w.writerows(sorted(labels.values(), key=lambda row: (row["rule"], row["key"])))
    print(f"{added} new finding(s) added to labels.csv ({len(labels)} total)")
    return 0


def tally(results: list[dict], labels: dict) -> tuple[dict[str, Counter], dict[str, Counter]]:
    """Per-rule and per-severity counts of TP / FP / unlabeled."""
    per_rule: dict[str, Counter] = defaultdict(Counter)
    per_sev: dict[str, Counter] = defaultdict(Counter)
    for r in results:
        for f in r["findings"]:
            label = labels.get(finding_key(r["id"], f), {}).get("label", "").upper() or "unlabeled"
            per_rule[f["rule"]][label] += 1
            per_sev[f["severity"]][label] += 1
    return per_rule, per_sev


def precision_tables(results: list[dict], labels: dict) -> list[str]:
    per_rule, per_sev = tally(results, labels)
    total = sum(per_rule.values(), Counter())
    out = [f"**Precision: {rate(total['TP'], total['TP'] + total['FP'])}**"
           + (f" ({total['unlabeled']} not yet labeled)" if total["unlabeled"] else ""), "",
           "| Rule | Findings | TP | FP | Precision (95% CI) |", "|---|---|---|---|---|"]
    for rule in sorted(per_rule, key=lambda r: (-sum(per_rule[r].values()), r)):
        c = per_rule[rule]
        n = c["TP"] + c["FP"]
        prec = f"{pct(c['TP'] / n)} ({pct(wilson(c['TP'], n)[0])}-{pct(wilson(c['TP'], n)[1])})" if n else "-"
        out.append(f"| `{rule}` | {sum(c.values())} | {c['TP']} | {c['FP']} | {prec} |")
    out += ["", "| Severity | TP | FP | Precision |", "|---|---|---|---|"]
    for sev in ("high", "medium", "low"):
        c = per_sev[sev]
        n = c["TP"] + c["FP"]
        out.append(f"| {sev} | {c['TP']} | {c['FP']} | {pct(c['TP'] / n) if n else '-'} |")
    return out


def dataset_table(results: list[dict]) -> list[str]:
    groups = Counter(r["group"] for r in results)
    out = ["| Group | PRs | PRs with ≥1 finding | Findings per 1,000 diff lines |", "|---|---|---|---|"]
    for g in sorted(groups):
        rs = [r for r in results if r["group"] == g]
        flagged = sum(1 for r in rs if r["findings"])
        per_k = 1000 * sum(len(r["findings"]) for r in rs) / max(1, sum(r["diff_lines"] for r in rs))
        out.append(f"| {g} | {len(rs)} | {flagged} | {per_k:.1f} |")
    return out


def main() -> int:
    if "--init-labels" in sys.argv:
        return init_labels()
    labels = load_labels()
    test = load_json("results_test.json") or []
    dev = load_json("results_dev.json") or []
    dev_before = load_json("dev/results_before.json") or []
    planted = (load_json("planted_results.json") or {}).get("results", [])

    out = ["# Benchmark results", "",
           "Labels were assigned by Claude and still need a human spot-check "
           "(see `LABELING.md`). Every label has a one-line reason in `labels.csv`.", ""]

    # ---- held-out test set: the headline
    if test:
        lines = [r["diff_lines"] for r in test]
        out += ["## Held-out test set (the real numbers)", "",
                f"{len(test)} public pull requests created in August 2026, collected **after** "
                "all tuning was finished and scanned once with the frozen tool. Diff size: "
                f"median {statistics.median(lines):.0f} lines, max {max(lines)}.", ""]
        out += precision_tables(test, labels)
        out += ["", "### Findings by group", ""] + dataset_table(test)
        out += ["", "Groups differ in repo size, language and PR size, so this describes the "
                "sample; it is not evidence that AI-written code is riskier."]

    # ---- recall
    if planted:
        core = [p for p in planted if not p["hard"]]
        hard = [p for p in planted if p["hard"]]
        out += ["", "## Recall (planted problems)", "",
                "Real PRs rarely contain a leaked key or a hallucinated package, so recall is "
                "measured by planting known problems, written the way they appear in real code, "
                "into copies of test-set PRs (`planted.py`).", "",
                f"**In-scope problems found: {rate(sum(p['found'] for p in core), len(core))}.**", "",
                f"{sum(p.get('in_existing_file', False) for p in core)} of the {len(core)} in-scope "
                "plants landed inside a file the PR already changed; the rest arrived as a new "
                "file (the PR had no file of that language), which is the easier case.", "",
                "Caveat: the same person wrote the rules and the plants, so this is an upper "
                "bound on recall, not an unbiased estimate. It does show the rules survive real "
                "surroundings (path filters, test-file handling, other findings).", "",
                f"Deliberately out-of-scope cases: {sum(p['found'] for p in hard)}/{len(hard)} found "
                "(expected: these show the design's limits).", "",
                "| Planted problem | Expected rule | Found? |", "|---|---|---|"]
        out += [f"| {p['id']}{' (out of scope)' if p['hard'] else ''} | `{p['expected']}` | "
                f"{'yes' if p['found'] else '**no**'} |" for p in planted]

    # ---- speed
    if test:
        secs = sorted(r["seconds"] for r in test)
        off = sorted(r["offline_seconds"] for r in test)
        p95 = secs[min(len(secs) - 1, math.ceil(0.95 * len(secs)) - 1)]
        out += ["", "## Speed", "",
                f"Per PR, wall-clock, including live PyPI/npm lookups: median "
                f"{statistics.median(secs):.2f}s, 95th percentile {p95:.2f}s, max {secs[-1]:.2f}s.",
                f"Without the network (`--offline`): median {1000 * statistics.median(off):.0f}ms, "
                f"max {1000 * off[-1]:.0f}ms. Nearly all the time is registry lookups, and it "
                "varies with network conditions.", ""]

    # ---- dev set
    if dev:
        out += ["## Development set (optimistic: the tool was fixed using it)", "",
                f"{len(dev)} PRs from September 2026. Labeling the first run exposed false "
                "positives (monorepo workspace packages, path aliases, `bun:` imports, "
                "conditional test skips, renamed tests, docs). Each was fixed with a regression "
                "test, then the set was re-run.", "",
                "### Before fixes", ""] + precision_tables(dev_before, labels) + [
                "", "### After fixes", ""] + precision_tables(dev, labels)

    with open(os.path.join(HERE, "RESULTS.md"), "w") as fh:
        fh.write("\n".join(out) + "\n")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
