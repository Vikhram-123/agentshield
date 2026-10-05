"""Diff reader: turn `git diff` output into the lines that were added.

A unified diff looks like this:

    diff --git a/app.py b/app.py
    --- a/app.py
    +++ b/app.py
    @@ -10,3 +10,4 @@ def main():
         unchanged line
    -    removed line
    +    added line

The `@@ -10,3 +10,4 @@` "hunk header" says: in the NEW file this chunk
starts at line 10. We count forward from there so every added line gets
its real line number, which is what lets the report say `app.py:12`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class AddedLine:
    number: int
    text: str


@dataclass
class FileDiff:
    path: str                 # path in the new version ("b/" side)
    old_path: str | None      # None when the file is brand new
    added: list[AddedLine] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    is_deleted: bool = False

    @property
    def is_new(self) -> bool:
        return self.old_path is None


def parse_diff(text: str) -> list[FileDiff]:
    files: list[FileDiff] = []
    current: FileDiff | None = None
    new_line = 0
    in_hunk = False

    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            # "diff --git a/x b/x": start a new file. The real paths come
            # from the ---/+++ lines below; this is a fallback.
            parts = raw.split(" b/", 1)
            path = parts[1] if len(parts) == 2 else raw.split()[-1]
            current = FileDiff(path=path, old_path=path)
            files.append(current)
            in_hunk = False
            continue
        if current is None:
            continue
        if not in_hunk and raw.startswith("--- "):
            src = raw[4:].strip()
            current.old_path = None if src == "/dev/null" else _strip_prefix(src)
            continue
        if not in_hunk and raw.startswith("+++ "):
            dst = raw[4:].strip()
            if dst == "/dev/null":
                current.is_deleted = True
            else:
                current.path = _strip_prefix(dst)
            continue
        m = HUNK_RE.match(raw)
        if m:
            new_line = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue  # metadata like "index abc..def" or "new file mode"
        if raw.startswith("+"):
            current.added.append(AddedLine(new_line, raw[1:]))
            new_line += 1
        elif raw.startswith("-"):
            current.removed.append(raw[1:])
        elif raw.startswith("\\"):
            pass  # "\ No newline at end of file"
        else:
            new_line += 1  # context line: exists in both versions

    return files


def _strip_prefix(path: str) -> str:
    path = path.split("\t", 1)[0]
    return path[2:] if path[:2] in ("a/", "b/") else path


def git_diff(base: str | None = None, staged: bool = False) -> str:
    """Run git and return the diff text.

    base=None   -> everything changed since the last commit (git diff HEAD)
    base="main" -> what this branch adds on top of main (git diff main...HEAD)
    staged=True -> only what is staged for the next commit
    """
    if staged:
        cmd = ["git", "diff", "--cached"]
    elif base:
        cmd = ["git", "diff", f"{base}...HEAD"]
    else:
        cmd = ["git", "diff", "HEAD"]
    result = subprocess.run(cmd + ["--no-color", "--unified=3"],
                            capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git diff failed")
    return result.stdout
