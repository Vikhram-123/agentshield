"""Project settings (.agentshield.toml) and inline `# agentshield: ignore` comments.

Every tool that flags things needs an escape hatch, or people turn it off
entirely. There are two, at different scopes:

  .agentshield.toml              whole-project rules, reviewed like code:
      fail_on = "medium"         # high | medium | low | never
      fail_score = 60            # also fail if the risk score reaches this
      ignore_paths = ["vendor/", "docs/**", "*.min.js"]
      ignore_rules = ["risky.no-tests", "secret.jwt"]
      allow_packages = ["acme-internal-sdk", "@acme/*"]
      new_package_days = 30

  key = "abc..."  # agentshield: ignore              one line, every rule
  eval(expr)      # agentshield: ignore[risky.dangerous-call]   one rule

Ignored findings are counted in a note, so suppression is never silent.
"""

from __future__ import annotations

import fnmatch
import os
import re
import tomllib
from dataclasses import dataclass, field

from .diff import FileDiff
from .findings import Finding
from .similarity import normalize

CONFIG_NAME = ".agentshield.toml"
SEVERITIES = ("high", "medium", "low", "never")
# "# agentshield: ignore" or "// agentshield: ignore[rule.a, rule.b]"
INLINE_RE = re.compile(r"agentshield:\s*ignore(?:\[([^\]]*)\])?", re.I)


class ConfigError(Exception):
    pass


@dataclass
class Config:
    fail_on: str | None = None          # None = use the CLI flag / default
    fail_score: int | None = None
    ignore_paths: list[str] = field(default_factory=list)
    ignore_rules: list[str] = field(default_factory=list)
    allow_packages: list[str] = field(default_factory=list)
    new_package_days: int = 30
    source: str | None = None           # which file this came from, for messages

    # ------------------------------------------------------------- questions

    def path_ignored(self, path: str) -> bool:
        for pattern in self.ignore_paths:
            if pattern.endswith("/"):           # "vendor/" = that folder, anywhere inside
                if path.startswith(pattern) or f"/{pattern}" in f"/{path}":
                    return True
            elif fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern):
                return True
        return False

    def rule_ignored(self, rule: str) -> bool:
        return any(_rule_matches(rule, r) for r in self.ignore_rules)

    def package_allowed(self, name: str) -> bool:
        n = normalize(name)
        return any(fnmatch.fnmatch(n, normalize(p)) for p in self.allow_packages)


def _rule_matches(rule: str, pattern: str) -> bool:
    """"secret" or "secret.*" covers every secret rule; "secret.jwt" just one."""
    pattern = pattern.strip().lower().removesuffix(".*")
    return rule == pattern or rule.startswith(pattern + ".")


# -------------------------------------------------------------------- loading

def load_config(repo_root: str = ".", path: str | None = None) -> Config:
    """Read the config file. No file is fine (defaults); a broken one is an error."""
    path = path or os.path.join(repo_root, CONFIG_NAME)
    if not os.path.exists(path):
        return Config()
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{path}: invalid TOML: {e}") from e
    return parse_config(data, source=path)


def parse_config(data: dict, source: str = CONFIG_NAME) -> Config:
    # Unknown keys are errors: a typo like "ignore_path" must not silently do nothing.
    known = {"fail_on", "fail_score", "ignore_paths", "ignore_rules",
             "allow_packages", "new_package_days"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{source}: unknown setting(s) {sorted(unknown)}; "
                          f"expected one of {sorted(known)}")
    cfg = Config(source=source)
    if "fail_on" in data:
        if data["fail_on"] not in SEVERITIES:
            raise ConfigError(f"{source}: fail_on must be one of {SEVERITIES}")
        cfg.fail_on = data["fail_on"]
    if "fail_score" in data:
        cfg.fail_score = _int(data, "fail_score", source, 0, 100)
    if "new_package_days" in data:
        cfg.new_package_days = _int(data, "new_package_days", source, 0, 3650)
    for key in ("ignore_paths", "ignore_rules", "allow_packages"):
        if key in data:
            value = data[key]
            if not (isinstance(value, list) and all(isinstance(v, str) for v in value)):
                raise ConfigError(f"{source}: {key} must be a list of strings")
            setattr(cfg, key, value)
    return cfg


def _int(data: dict, key: str, source: str, lo: int, hi: int) -> int:
    value = data[key]
    if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
        raise ConfigError(f"{source}: {key} must be a whole number from {lo} to {hi}")
    return value


# ------------------------------------------------------------------ applying

def apply_ignores(findings: list[Finding], files: list[FileDiff],
                  config: Config) -> tuple[list[Finding], list[str]]:
    """Drop findings ignored by config rules or inline comments.

    Returns (kept findings, notes saying how many were dropped).
    """
    added_text = {(f.path, a.number): a.text for f in files for a in f.added}
    kept: list[Finding] = []
    by_config = by_inline = 0
    for f in findings:
        if config.rule_ignored(f.rule):
            by_config += 1
        elif _inline_ignored(f, added_text.get((f.file, f.line))):
            by_inline += 1
        else:
            kept.append(f)
    notes = []
    if by_config:
        notes.append(f"{by_config} finding(s) hidden by ignore_rules in {config.source}.")
    if by_inline:
        notes.append(f"{by_inline} finding(s) hidden by inline 'agentshield: ignore' comments.")
    return kept, notes


def _inline_ignored(f: Finding, line_text: str | None) -> bool:
    if not line_text:
        return False
    m = INLINE_RE.search(line_text)
    if not m:
        return False
    if m.group(1) is None:
        return True  # bare "agentshield: ignore" = every rule on this line
    return any(_rule_matches(f.rule, r) for r in m.group(1).split(",") if r.strip())
