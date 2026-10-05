"""Command line entry point:  agentshield scan [options]"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .checks.packages import check_packages
from .checks.secrets import check_secrets
from .diff import git_diff, parse_diff
from .findings import Severity
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
    s.add_argument("--fail-on", choices=["high", "medium", "low", "never"], default="high",
                   help="exit with code 1 if a finding is at least this severe (default: high)")
    s.add_argument("--repo", default=".", help="repository root (default: current folder)")
    s.add_argument("--no-color", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

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

    files = [f for f in parse_diff(text) if not f.is_deleted]
    registry = None if args.offline else Registry()
    findings, notes = check_packages(files, registry, repo_root=args.repo)
    # The other checks only need the diff. Each returns (findings, notes).
    for check in (check_secrets,):
        more_findings, more_notes = check(files)
        findings += more_findings
        notes += more_notes

    if args.format == "json":
        out = render_json(findings, notes, len(files))
    elif args.format == "markdown":
        out = render_markdown(findings, notes, len(files))
    else:
        out = render_text(findings, notes, len(files), color=False if args.no_color else None)
    sys.stdout.write(out)

    # Exit code lets CI block the merge: 0 = pass, 1 = problems found.
    if args.fail_on != "never":
        threshold = {"high": 0, "medium": 1, "low": 2}[args.fail_on]
        rank = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        if any(rank[f.severity] <= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
