"""Command line entry point:  agentshield scan [options]"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks.packages import check_packages
from .checks.risky import check_risky
from .checks.secrets import check_secrets
from .config import ConfigError, apply_ignores, load_config
from .diff import git_diff, parse_diff
from .findings import Severity, risk_score
from .registry import Registry
from .report import render_json, render_markdown, render_text


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="agentshield",
                                description="Catch risky AI-written code before it merges.")
    p.add_argument("--version", action="version", version=f"agentshield {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="scan a code change")
    src = s.add_mutually_exclusive_group()
    src.add_argument("--diff", metavar="FILE",
                     help="read a diff from FILE ('-' for stdin) instead of running git")
    src.add_argument("--base", metavar="REF",
                     help="scan what this branch adds on top of REF (e.g. main)")
    src.add_argument("--staged", action="store_true", help="scan only staged changes")
    s.add_argument("--format", choices=["text", "markdown", "json"], default="text")
    s.add_argument("--offline", action="store_true",
                   help="don't contact PyPI/npm (typo checks only)")
    s.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default=None,
                   help="exit with code 1 if a finding is at least this severe "
                        "(default: fail_on from the config, else high)")
    s.add_argument("--config", metavar="FILE",
                   help="settings file (default: .agentshield.toml in --repo)")
    s.add_argument("--repo", default=".", help="repository root (default: current folder)")
    s.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        config = load_config(args.repo, args.config)
    except (ConfigError, OSError) as e:
        print(f"agentshield: {e}", file=sys.stderr)
        return 2

    try:
        if args.diff == "-":
            text = sys.stdin.read()
        elif args.diff:
            with open(args.diff, encoding="utf-8") as fh:
                text = fh.read()
        else:
            text = git_diff(base=args.base, staged=args.staged)
    except (OSError, RuntimeError) as e:
        print(f"agentshield: {e}", file=sys.stderr)
        return 2

    # Deleted files are kept: the risky-change check needs to see deleted tests.
    files = parse_diff(text)
    if text.strip() and not files:
        # Saying "CLEAN" about something we couldn't read would be a lie.
        print("agentshield: input is not a unified diff (expected 'diff --git' headers)",
              file=sys.stderr)
        return 2
    kept = [f for f in files if not config.path_ignored(f.path)]
    skipped, files = len(files) - len(kept), kept
    scanned = len([f for f in files if not f.is_deleted])
    registry = None if args.offline else Registry()
    findings, notes = check_packages(files, registry, repo_root=args.repo,
                                     new_package_days=config.new_package_days,
                                     is_allowed=config.package_allowed)
    # The other checks only need the diff. Each returns (findings, notes).
    for check in (check_secrets, check_risky):
        more_findings, more_notes = check(files)
        findings += more_findings
        notes += more_notes
    findings, ignore_notes = apply_ignores(findings, files, config)
    notes += ignore_notes
    if skipped:
        notes.append(f"{skipped} file(s) skipped by ignore_paths in {config.source}.")

    if args.format == "json":
        out = render_json(findings, notes, scanned)
    elif args.format == "markdown":
        out = render_markdown(findings, notes, scanned)
    else:
        out = render_text(findings, notes, scanned, color=False if args.no_color else None)
    sys.stdout.write(out)

    # Exit code lets CI block the merge: 0 = pass, 1 = problems found.
    fail_on = args.fail_on or config.fail_on or "high"
    if fail_on == "never":
        return 0
    threshold = {"high": 0, "medium": 1, "low": 2}[fail_on]
    rank = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    if any(rank[f.severity] <= threshold for f in findings):
        return 1
    if config.fail_score is not None and findings and risk_score(findings) >= config.fail_score:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
