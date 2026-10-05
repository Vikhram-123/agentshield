"""Turn findings into something a human (or a CI system) can read."""

from __future__ import annotations

import json
import os
import sys

from .findings import Finding, Severity, risk_label, risk_score

ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
ICONS = {Severity.HIGH: "✖", Severity.MEDIUM: "⚠", Severity.LOW: "•"}
COLORS = {Severity.HIGH: "\033[31m", Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m"}
BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (ORDER[f.severity], f.file, f.line or 0))


def _loc(f: Finding) -> str:
    return f"{f.file}:{f.line}" if f.line else f.file


def render_text(findings: list[Finding], notes: list[str], files_scanned: int,
                color: bool | None = None) -> str:
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    c = (lambda code, s: f"{code}{s}{RESET}") if color else (lambda code, s: s)

    score = risk_score(findings)
    label = risk_label(score)
    head_color = {"HIGH": COLORS[Severity.HIGH], "MEDIUM": COLORS[Severity.MEDIUM]}.get(label, "\033[32m")
    lines = [c(BOLD, "AgentShield report") + f"  ({files_scanned} file(s) scanned)",
             c(head_color + BOLD, f"Risk {score}/100 ({label})"), ""]
    if not findings:
        lines.append(c("\033[32m", "✔ No problems found."))
    for f in _sorted(findings):
        tag = f.rule.upper().replace(".", " ").replace("-", " ")
        lines.append(c(COLORS[f.severity] + BOLD, f"{ICONS[f.severity]} {tag}") + f"   {_loc(f)}")
        lines.append(f"  {f.message}")
        lines.append(c(DIM, f"  Fix: {f.fix}"))
        lines.append("")
    for n in notes:
        lines.append(c(DIM, f"note: {n}"))
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(findings: list[Finding], notes: list[str], files_scanned: int) -> str:
    score = risk_score(findings)
    out = [f"## 🛡️ AgentShield: Risk {score}/100 ({risk_label(score)})", "",
           f"Scanned {files_scanned} changed file(s).", ""]
    if not findings:
        out.append("✅ No problems found.")
    else:
        out += ["| | Issue | Location | Fix |", "|---|---|---|---|"]
        for f in _sorted(findings):
            msg = f.message.replace("|", "\\|")
            fix = f.fix.replace("|", "\\|")
            out.append(f"| {ICONS[f.severity]} {f.severity.value} | {msg} | `{_loc(f)}` | {fix} |")
    if notes:
        out += ["", "<details><summary>Notes</summary>", ""] + [f"- {n}" for n in notes] + ["", "</details>"]
    return "\n".join(out) + "\n"


def render_json(findings: list[Finding], notes: list[str], files_scanned: int) -> str:
    score = risk_score(findings)
    return json.dumps({
        "risk_score": score,
        "risk_label": risk_label(score),
        "files_scanned": files_scanned,
        "findings": [f.to_dict() for f in _sorted(findings)],
        "notes": notes,
    }, indent=2) + "\n"
