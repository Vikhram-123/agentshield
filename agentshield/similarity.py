"""Typosquat detection: how many keystrokes apart are two package names?

We use "optimal string alignment" distance: the number of single-character
inserts, deletes, substitutions or swaps of neighbours needed to turn one
string into the other.

    requests -> reqeusts   1 (swap "u" and "e")
    requests -> request    1 (delete "s")
    numpy    -> numpi      1 (substitute)
"""

from __future__ import annotations

import re


def normalize(name: str) -> str:
    """PyPI treats Foo_Bar, foo.bar and foo-bar as the same name (PEP 503)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def edit_distance(a: str, b: str) -> int:
    # Classic dynamic programming table: d[i][j] = distance between
    # the first i chars of a and the first j chars of b.
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1,         # delete
                          d[i][j - 1] + 1,         # insert
                          d[i - 1][j - 1] + cost)  # substitute
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)  # swap neighbours
    return d[len(a)][len(b)]


def max_typo_distance(name: str) -> int:
    """Short names collide by accident ("six" vs "sip"), so allow fewer edits."""
    if len(name) < 4:
        return 0
    if len(name) <= 6:
        return 1
    return 2


def closest(name: str, candidates: set[str]) -> tuple[str, int] | None:
    """The most similar popular name within typo range, or None."""
    n = normalize(name)
    limit = max_typo_distance(n)
    if limit == 0 or n in candidates:
        return None
    best: tuple[str, int] | None = None
    for c in candidates:
        if abs(len(c) - len(n)) > limit:
            continue  # cheap skip: length gap alone exceeds the limit
        dist = edit_distance(n, c)
        if dist <= limit and (best is None or dist < best[1]):
            best = (c, dist)
    return best
