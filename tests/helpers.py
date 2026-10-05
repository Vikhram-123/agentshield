"""Small builders shared by the tests."""

import random

from agentshield.diff import parse_diff


def make_diff(path, added, removed=(), new_file=False):
    """A one-file unified diff that adds `added` lines (and removes `removed`)."""
    old = "/dev/null" if new_file else f"a/{path}"
    body = [f"-{r}" for r in removed] + [f"+{a}" for a in added]
    return (f"diff --git a/{path} b/{path}\n--- {old}\n+++ b/{path}\n"
            f"@@ -1,{len(removed)} +1,{len(added)} @@\n" + "\n".join(body) + "\n")


def files_from(*diffs):
    return parse_diff("".join(diffs))


def fake_secret(n, seed=0, alphabet=""):
    """Deterministic random-looking string.

    Tests build fake keys at runtime ("AKIA" + fake_secret(16)) so this repo's
    source never contains anything shaped like a real key. That keeps GitHub's
    push protection quiet and stops AgentShield from flagging its own tests.
    """
    alphabet = alphabet or "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))
