"""The Finding: one problem AgentShield found, plus how to fix it.

Every check returns a list of Findings. Keeping one shared shape means the
report, the score and the JSON output never need to know which check ran.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"      # likely a real problem: block the merge
    MEDIUM = "medium"  # suspicious: a human should look
    LOW = "low"        # worth knowing, rarely urgent

    @property
    def weight(self) -> int:
        """Points this severity adds to the 0-100 risk score."""
        return {"high": 40, "medium": 15, "low": 5}[self.value]


@dataclass(frozen=True)
class Finding:
    rule: str            # stable id, e.g. "package.not-found"
    severity: Severity
    file: str
    line: int | None
    message: str         # what is wrong
    fix: str             # what to do about it

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


def risk_score(findings: list[Finding]) -> int:
    """Combine findings into one 0-100 number (capped, so 3 highs = 100)."""
    return min(100, sum(f.severity.weight for f in findings))


def risk_label(score: int) -> str:
    if score >= 60:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "CLEAN"
