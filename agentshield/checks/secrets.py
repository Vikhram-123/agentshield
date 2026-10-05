"""Leaked secret check.

AI tools love to "just make it work" by pasting a real API key into the code.
Once that is pushed, the key is in git history forever, so the only real fix
is to revoke it. This check runs on every added line and works in two layers:

  1. KNOWN FORMATS. Most providers give their keys a recognisable prefix
     (AWS "AKIA...", GitHub "ghp_...", Stripe "sk_live_..."). A regex for each
     format is very precise: a match is almost certainly a real key.
  2. ENTROPY. For keys with no known format, we look at values assigned to
     secret-sounding names (api_key = "...") and measure how random the value
     looks (Shannon entropy). Random gibberish is a key; a word is a label.

Placeholders ("your-key-here", "xxxx", the AWS docs example key) are skipped,
and secrets are masked in the output: the report must not leak them again.
"""

from __future__ import annotations

import math
import os
import re
from collections import Counter
from dataclasses import dataclass

from ..diff import FileDiff
from ..findings import Finding, Severity

ROTATE = "it's in git history now, so deleting the line is not enough"


@dataclass(frozen=True)
class SecretPattern:
    rule: str
    name: str                    # human name used in the message
    regex: re.Pattern
    severity: Severity
    fix: str
    group: int = 0               # which regex group holds the secret itself
    needs_mixed: bool = False    # require upper+lower+digit (cuts look-alike words)


def _p(rule, name, pattern, severity, fix, **kw) -> SecretPattern:
    return SecretPattern(rule, name, re.compile(pattern), severity, fix, **kw)


# Order matters: more specific patterns first (Anthropic's "sk-ant-" before
# OpenAI's "sk-"). Only the first pattern that matches a span is reported.
PATTERNS: list[SecretPattern] = [
    _p("secret.private-key", "private key",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       Severity.HIGH,
       f"Remove the key file from the repo and generate a new key pair ({ROTATE}). "
       "Load keys from a secrets manager or a file listed in .gitignore."),
    _p("secret.aws-key", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
       Severity.HIGH,
       f"Deactivate this key in AWS IAM and create a new one ({ROTATE}). "
       "Use environment variables, an IAM role or AWS Secrets Manager instead."),
    _p("secret.aws-key", "AWS secret access key",
       r"(?i)aws_?secret_?(?:access_?)?key\W{0,4}([A-Za-z0-9/+=]{40})\b",
       Severity.HIGH,
       f"Deactivate this key in AWS IAM and create a new one ({ROTATE}). "
       "Use environment variables, an IAM role or AWS Secrets Manager instead.",
       group=1),
    _p("secret.github-token", "GitHub token",
       r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
       Severity.HIGH,
       f"Revoke the token at github.com/settings/tokens ({ROTATE}). "
       "In Actions, use the built-in GITHUB_TOKEN or a repository secret."),
    _p("secret.anthropic-key", "Anthropic API key",
       r"\bsk-ant-[a-z0-9]+-[A-Za-z0-9_-]{20,}",
       Severity.HIGH,
       f"Delete this key in the Anthropic Console and create a new one ({ROTATE}). "
       "Read it from the ANTHROPIC_API_KEY environment variable."),
    _p("secret.openai-key", "OpenAI API key",
       r"(?<![\w-])sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}",
       Severity.HIGH,
       f"Delete this key on the OpenAI API keys page and create a new one ({ROTATE}). "
       "Read it from the OPENAI_API_KEY environment variable.",
       needs_mixed=True),
    # Only live keys: test keys are in SAFE_PREFIXES below.
    _p("secret.stripe-key", "Stripe live secret key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}",
       Severity.HIGH,
       f"Roll this key in the Stripe dashboard ({ROTATE}). "
       "Keep it in an environment variable on the server only."),
    _p("secret.slack-token", "Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}",
       Severity.HIGH,
       f"Revoke the token in your Slack app settings ({ROTATE}) and load it from the environment."),
    _p("secret.slack-webhook", "Slack webhook URL",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
       Severity.MEDIUM,
       "Anyone with this URL can post to your channel. Regenerate the webhook "
       "and load it from the environment."),
    # Google browser keys are sometimes meant to be public (Firebase), so MEDIUM.
    _p("secret.google-api-key", "Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b",
       Severity.MEDIUM,
       "If this key is server-side, delete it in Google Cloud Console > Credentials and "
       "make a new one. If it must ship to browsers, restrict it by HTTP referrer and API."),
    # JWTs are often short-lived or test tokens, so MEDIUM.
    _p("secret.jwt", "JSON Web Token",
       r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
       Severity.MEDIUM,
       "Don't hardcode tokens: if it's long-lived, revoke it or rotate the signing key, "
       "and fetch tokens at runtime instead."),
    _p("secret.db-url", "database URL with a password",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mssql|mongodb(?:\+srv)?|rediss?|amqps?)://"
       r"[^:/\s@]+:([^@\s/]+)@([^/\s:\"']+)",
       Severity.HIGH,
       f"Change this database password ({ROTATE}) and read the URL from an environment "
       "variable such as DATABASE_URL.",
       group=1),
]

# --------------------------------------------------------------- placeholders

PLACEHOLDER_WORDS = ("xxx", "your", "example", "placeholder", "changeme", "change_me",
                     "change-me", "dummy", "sample", "fake", "redacted", "replace",
                     "insert", "todo", "<", ">", "${", "{{", "%(", "...", "***")
# Passwords that are obviously local-dev defaults, not leaks.
DEFAULT_PASSWORDS = {"password", "pass", "passwd", "pwd", "secret", "root", "admin",
                     "postgres", "mysql", "user", "test", "guest", "dev", "local"}
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
# Key formats that are safe to commit: Stripe test keys can't move real money
# and publishable keys are meant to ship to browsers.
SAFE_PREFIXES = ("sk_test_", "rk_test_", "pk_test_", "pk_live_")


def is_placeholder(value: str) -> bool:
    low = value.lower()
    if any(w in low for w in PLACEHOLDER_WORDS):
        return True
    if low.startswith(SAFE_PREFIXES):
        return True
    if low.startswith(("$", "%", "{")):
        return True  # $ENV_VAR, %s, {var}: filled in at runtime
    # "aaaaaaaa..." or "0000..." : one character repeated
    if len(set(low.strip("-_"))) <= 2:
        return True
    return False


# ------------------------------------------------------------------- entropy

def shannon_entropy(s: str) -> float:
    """Average bits of information per character.

    H = -sum(p * log2(p)) over each distinct character, where p is how often
    it appears. "aaaa" scores 0; a random base64 string scores about 4.5-6.
    """
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


ENTROPY_THRESHOLD = 3.5
MIN_SECRET_LEN = 16
SECRET_WORDS = (r"secret|token|passw(?:or)?d|pwd|api[_-]?key|apikey|access[_-]?key"
                r"|private[_-]?key|credential|auth[_-]?key")
# Cheap first pass: most lines contain none of the words, so skip them fast.
SECRET_WORD_RE = re.compile(SECRET_WORDS, re.I)
# (?<![\w.-]) anchors the name at its start, so the regex doesn't retry at
# every character inside a long identifier (that made it 10x slower).
SECRET_NAME = rf"(?<![\w.-])[\w.-]*(?:{SECRET_WORDS})[\w.-]*"
# name = "value"  |  name: 'value'  |  "name": "value"  |  name := "value"
QUOTED_ASSIGN_RE = re.compile(
    rf"""(?i)["']?({SECRET_NAME})["']?\s*(?::=|=>|=|:)\s*[rbf]?["'`]([^"'`\s]+)["'`]""")
# NAME=value with no quotes: only in .env / YAML / ini style files.
BARE_ASSIGN_RE = re.compile(rf"""(?i)^\s*(?:export\s+)?({SECRET_NAME})\s*[=:]\s*([^\s"'#]+)\s*(?:#.*)?$""")
BARE_OK_EXTS = (".env", ".yml", ".yaml", ".ini", ".cfg", ".conf", ".properties", ".toml")


def looks_random(value: str) -> bool:
    """Is this value random gibberish (a key) rather than a word or a reference?"""
    if len(value) < MIN_SECRET_LEN:
        return False
    if "://" in value or value.startswith(("/", "./", "~")):
        return False  # URLs and paths
    if not (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
        return False  # real keys almost always mix letters and digits
    return shannon_entropy(value) >= ENTROPY_THRESHOLD


# ---------------------------------------------------------------- file rules

# Files that never hold hand-written secrets but are full of random-looking
# hashes (lockfile integrity checksums, minified code).
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
              "pipfile.lock", "cargo.lock", "go.sum", "composer.lock", "uv.lock"}
SKIP_EXTS = (".min.js", ".min.css", ".map", ".svg", ".lock")
TEST_DIR_RE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|mocks?|examples?)/", re.I)
TEST_FILE_RE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.\w+|[^/]*\.(test|spec)\.\w+|[^/]*\.(example|sample|template))$", re.I)


def is_test_path(path: str) -> bool:
    return bool(TEST_DIR_RE.search(path) or TEST_FILE_RE.search(path))


def mask(secret: str) -> str:
    """Show only the first 4 characters (fewer for short secrets like passwords)."""
    shown = 4 if len(secret) >= 12 else 0
    return secret[:shown] + "*" * 8


# ------------------------------------------------------------------ the check

def check_secrets(files: list[FileDiff]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    test_hits = 0
    for f in files:
        base = os.path.basename(f.path).lower()
        if base in SKIP_FILES or base.endswith(SKIP_EXTS):
            continue
        in_test = is_test_path(f.path)
        bare_ok = base.startswith(".env") or base.endswith(BARE_OK_EXTS)
        for added in f.added:
            line_findings = _scan_line(f.path, added.number, added.text, bare_ok, in_test)
            if in_test and line_findings:
                test_hits += len(line_findings)
            findings += line_findings
    notes = []
    if test_hits:
        notes.append(f"{test_hits} possible secret(s) in test/example files were "
                     "reported as LOW: they are often fake, but check them.")
    return findings, notes


def _scan_line(path: str, num: int, text: str, bare_ok: bool, in_test: bool) -> list[Finding]:
    out: list[Finding] = []
    taken: list[tuple[int, int]] = []  # spans already reported, so one key = one finding

    for p in PATTERNS:
        for m in p.regex.finditer(text):
            secret = m.group(p.group)
            if _overlaps(m.span(), taken) or _skip_known(p, m, secret):
                continue
            taken.append(m.span())
            sev = Severity.LOW if in_test else p.severity
            where = " in a test/example file" if in_test else ""
            out.append(Finding(p.rule, sev, path, num,
                               f"Hardcoded {p.name}{where}: {mask(secret)}", p.fix))

    if in_test:
        return out  # entropy guesses in test files are mostly fake data: too noisy
    if not SECRET_WORD_RE.search(text):
        return out
    candidates = [(m.span(2), m.group(1), m.group(2)) for m in QUOTED_ASSIGN_RE.finditer(text)]
    if bare_ok:
        candidates += [(m.span(2), m.group(1), m.group(2)) for m in BARE_ASSIGN_RE.finditer(text)]
    for span, name, value in candidates:
        if _overlaps(span, taken) or is_placeholder(value) or not looks_random(value):
            continue
        taken.append(span)
        out.append(Finding(
            "secret.high-entropy", Severity.MEDIUM, path, num,
            f'"{name}" is set to a random-looking value ({mask(value)}, entropy '
            f"{shannon_entropy(value):.1f} bits/char). This looks like a hardcoded secret.",
            "If this is a real credential, rotate it and load it from an environment "
            "variable or secrets manager instead."))
    return out


def _skip_known(p: SecretPattern, m: re.Match, secret: str) -> bool:
    if p.rule == "secret.private-key":
        return False  # the header itself is the evidence; there's no value to judge
    if is_placeholder(secret):
        return True
    if p.needs_mixed and not (re.search(r"[a-z]", secret) and re.search(r"[A-Z]", secret)
                              and re.search(r"\d", secret)):
        return True
    if p.rule == "secret.db-url":
        host = m.group(2).lower()
        return secret.lower() in DEFAULT_PASSWORDS or host in LOCAL_HOSTS
    return False


def _overlaps(span: tuple[int, int], taken: list[tuple[int, int]]) -> bool:
    return any(span[0] < e and s < span[1] for s, e in taken)

