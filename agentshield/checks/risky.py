"""Risky change check: code that is fine to write but dangerous to merge unreviewed.

Unlike a leaked key, nothing here is wrong for certain. Dropping a column can
be exactly what you meant. So these findings mostly say "a human should look
at this", with HIGH kept for changes that can't be undone (data loss).

Rules (each has a stable id):
  risky.auth-change        a login/permission file changed              LOW
  risky.auth-guard-removed @login_required etc. removed, not re-added    MEDIUM
  risky.destructive-migration  DROP TABLE / DROP COLUMN / TRUNCATE      HIGH
  risky.test-deleted       a test file or test function removed          MEDIUM
  risky.test-skipped       a test was skipped / .only'd                  MEDIUM
  risky.no-tests           a sizeable source change with no test changes LOW
  risky.insecure-setting   verify=False, DEBUG=True, CORS "*" ...        MEDIUM
  risky.dangerous-call     eval, exec, shell=True, pickle.loads ...      MEDIUM
"""

from __future__ import annotations

import os
import re
from collections import Counter

from ..diff import FileDiff
from ..findings import Finding, Severity
from ..paths import is_fixture_path, is_source_path, is_test_path

# A source change smaller than this doesn't need its own test.
NO_TESTS_MIN_LINES = 10


DOC_EXTS = (".md", ".rst", ".txt", ".adoc")


def _is_comment(text: str) -> bool:
    return text.lstrip().startswith(("#", "//", "/*", "*", "--", "<!--"))


# ------------------------------------------------------------ code vs text
# `x = eval(s)` is a risk; `msg = "never use eval()"` is just text. These two
# helpers tell them apart, so a rule only fires when its match starts in code.

def _in_string(text: str, pos: int) -> bool:
    """Is position `pos` inside a quoted string on this line?"""
    quote = None
    i = 0
    while i < pos:
        if quote:
            if text[i] == "\\":
                i += 2  # skip the escaped character
                continue
            if text.startswith(quote, i):
                i += len(quote)
                quote = None
                continue
            i += 1
        else:
            for q in ('"""', "'''", '"', "'", "`"):
                if text.startswith(q, i):
                    quote = q
                    i += len(q)
                    break
            else:
                i += 1
    return quote is not None


def _docstring_lines(lines: list[str]) -> list[bool]:
    """For each line: is it inside a multi-line Python docstring?

    An odd number of triple quotes on a line opens (or closes) one. Lines in
    between are prose, not code.
    """
    inside = False
    flags = []
    for text in lines:
        toggles = (text.count('"""') + text.count("'''")) % 2 == 1
        flags.append(inside or toggles)
        if toggles:
            inside = not inside
    return flags


def _code_match(rx: re.Pattern, text: str) -> re.Match | None:
    """First match of rx that starts in code, not inside a string."""
    return next((m for m in rx.finditer(text) if not _in_string(text, m.start())), None)


# ------------------------------------------------------------ authentication

# "auth" but not "author"; no "session" (usually a database session).
AUTH_PATH_RE = re.compile(r"(?i)(^|[/_.-])(auth|authn|authz|authenticat\w*|authoriz\w*|login|logout|"
                          r"sign_?in|sign_?up|permissions?|rbac|acl|oauth2?|sso|saml|passwords?|"
                          r"credentials?)([/_.-]|$)")
# Lines that *enforce* access control. Removing one opens a door.
AUTH_GUARD_RE = re.compile(
    r"@(login_required|permission_required|user_passes_test|staff_member_required|"
    r"requires_auth|auth_required|jwt_required|admin_required|authenticated|"
    r"PreAuthorize|Secured|RolesAllowed)\b|"
    r"\[Authorize\b|permission_classes\s*=|IsAuthenticated|IsAdminUser|"
    r"Depends\(\s*get_current_(active_)?user|"
    r"\b(requireAuth|ensureAuthenticated|isAuthenticated|verifyToken|checkPermission|"
    r"authorize|require_login|has_perm|hasPermission)\b")


def _auth_findings(f: FileDiff) -> list[Finding]:
    out: list[Finding] = []
    still_there = Counter(_norm(a.text) for a in f.added)
    for r in f.removed:
        if _is_comment(r.text) or not _code_match(AUTH_GUARD_RE, r.text):
            continue
        key = _norm(r.text)
        if still_there[key] > 0:  # moved or reformatted, not removed
            still_there[key] -= 1
            continue
        out.append(Finding(
            "risky.auth-guard-removed", Severity.MEDIUM, f.path, r.number,
            f'An access check was removed: "{r.text.strip()[:80]}". '
            "This can make a page or API reachable without logging in.",
            "Confirm the endpoint is still protected (for example by middleware), "
            "and add a test that an anonymous user is rejected."))
    if not out and (f.added or f.removed) and AUTH_PATH_RE.search(f.path) \
            and is_source_path(f.path):
        line = f.added[0].number if f.added else None
        out.append(Finding(
            "risky.auth-change", Severity.LOW, f.path, line,
            "This change touches authentication or permission code.",
            "Get a careful human review: bugs here let the wrong people in."))
    return out


def _norm(text: str) -> str:
    return re.sub(r"\s+", "", text)


# --------------------------------------------------------------- migrations

DESTRUCTIVE_RE = re.compile(
    r"(?i:\b(DROP\s+(TABLE|COLUMN|DATABASE|SCHEMA)|TRUNCATE\s+TABLE|"   # SQL, any case
    r"ALTER\s+TABLE\s+\S+\s+DROP)\b)|"
    r"\bop\.drop_(table|column)\b|"                                    # Alembic
    r"\bmigrations\.(RemoveField|DeleteModel)\b|"                      # Django
    r"^\s*(drop_table|remove_columns?)\b|"                             # Rails
    r"\.(dropTable|dropColumn|dropColumns|removeColumn|dropTableIfExists)\s*\(")  # Knex/Sequelize
# Where the "undo" half of a migration starts and stops. Dropping a table in
# downgrade() just reverses a create, so that's normal.
DOWN_START_RE = re.compile(r"\bdef\s+(downgrade|down)\b|exports\.down\b|\basync\s+down\s*\(|"
                           r"\bfunction\s+down\s*\(|\bdown\s*:\s*(async\s*)?(\(|function)|"
                           r"(?i:--\s*\+?migrate[:\s]*down)")
UP_START_RE = re.compile(r"\bdef\s+(upgrade|up)\b|exports\.up\b|\basync\s+up\s*\(|"
                         r"\bfunction\s+up\s*\(|\bup\s*:\s*(async\s*)?(\(|function)|"
                         r"(?i:--\s*\+?migrate[:\s]*up)")


def _migration_findings(f: FileDiff) -> list[Finding]:
    base = os.path.basename(f.path).lower()
    if (is_test_path(f.path) or f.path.endswith(DOC_EXTS)
            or base.endswith((".down.sql", "_down.sql")) or base == "down.sql"):
        return []
    out: list[Finding] = []
    in_down = False
    in_doc = _docstring_lines([a.text for a in f.added])
    for a, doc in zip(f.added, in_doc):
        if doc:
            continue
        if DOWN_START_RE.search(a.text):
            in_down = True
        elif UP_START_RE.search(a.text):
            in_down = False
        m = DESTRUCTIVE_RE.search(a.text)
        if m and not in_down and not _is_comment(a.text):
            out.append(Finding(
                "risky.destructive-migration", Severity.HIGH, f.path, a.number,
                f'Destructive database change: "{a.text.strip()[:80]}". '
                "Once this runs in production the data is gone.",
                "Back up the data first, make sure no deployed code still reads it, "
                "and consider a two-step change (stop using it, then drop it later)."))
    return out


# -------------------------------------------------------------------- tests

TEST_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(test\w*)\s*\(|"
                         r"\b(?:it|test)\s*\(\s*['\"`]([^'\"`]+)['\"`]|"
                         r"^\s*func\s+(Test\w+)\s*\(")
SKIP_RE = re.compile(r"@(pytest\.mark\.skip|unittest\.skip|skip)\b|"
                     r"\b(it|test|describe|context)\.(skip|only)\s*\(|"
                     r"\b(xit|xdescribe|xtest)\s*\(|@Disabled\b|@Ignore\b|"
                     r"\bt\.Skip(Now|f)?\s*\(|self\.skipTest\s*\(")


def _test_findings(f: FileDiff) -> list[Finding]:
    if not is_test_path(f.path):
        return []
    if f.is_deleted:
        return [Finding("risky.test-deleted", Severity.MEDIUM, f.path, None,
                        "A whole test file was deleted.",
                        "Make sure the tested code was removed too, or that the tests "
                        "moved elsewhere. Deleting failing tests hides bugs.")]
    out: list[Finding] = []
    added_names = {_test_name(a.text) for a in f.added} - {None}
    for r in f.removed:
        name = _test_name(r.text)
        if name and name not in added_names:
            out.append(Finding(
                "risky.test-deleted", Severity.MEDIUM, f.path, r.number,
                f'Test "{name}" was removed.',
                "Check that it was obsolete, not failing. AI tools sometimes delete "
                "a failing test instead of fixing the code."))
    in_doc = _docstring_lines([a.text for a in f.added])
    for a, doc in zip(f.added, in_doc):
        m = None if doc or _is_comment(a.text) else _code_match(SKIP_RE, a.text)
        if m:
            only = ".only" in m.group(0)
            out.append(Finding(
                "risky.test-skipped", Severity.MEDIUM, f.path, a.number,
                ("A test was marked .only, so every other test in the file stops running."
                 if only else f'A test was disabled ("{m.group(0).strip()}").'),
                "Remove the .only before merging." if only else
                "Fix the test or the code instead, or link an issue explaining why it's skipped."))
    return out


def _test_name(text: str) -> str | None:
    m = TEST_DEF_RE.search(text)
    return next((g for g in m.groups() if g), None) if m else None


def _no_tests_finding(files: list[FileDiff]) -> list[Finding]:
    if any(is_test_path(f.path) for f in files):
        return []
    sizes = Counter()
    for f in files:
        if is_source_path(f.path) and not f.is_deleted:
            sizes[f.path] = sum(1 for a in f.added if a.text.strip())
    total = sum(sizes.values())
    if total < NO_TESTS_MIN_LINES:
        return []
    biggest = sizes.most_common(1)[0][0]
    return [Finding("risky.no-tests", Severity.LOW, biggest, None,
                    f"{total} line(s) of source code were added across {len(sizes)} file(s), "
                    "but no tests were added or changed.",
                    "Add a test that exercises the new behaviour (including a failure case).")]


# ------------------------------------------------------- settings and calls

CORS_RE = re.compile(r"(?i)(Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*|"
                     r"CORS_(ORIGIN_)?ALLOW_ALL(_ORIGINS)?\s*=\s*True|"
                     r"allow_origins\s*=\s*\[\s*['\"]\*['\"]|origins?\s*[:=]\s*['\"]\*['\"]|"
                     r"\bcors\(\s*\))")
NODE_TLS_RE = re.compile(r"NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*\]?\s*=\s*['\"]?0")
# Settings whose evidence is itself a string ("Access-Control-Allow-Origin",
# os.environ["NODE_TLS_..."]), so the match may start inside quotes.
MAY_START_IN_STRING = (CORS_RE, NODE_TLS_RE)
INSECURE_SETTINGS = [
    (re.compile(r"\bverify\s*=\s*False\b"),
     "TLS certificate checking is turned off (verify=False), allowing man-in-the-middle attacks.",
     "Remove verify=False. If you use a private CA, pass verify='/path/to/ca.pem'."),
    (re.compile(r"\b(ssl\._create_unverified_context|CERT_NONE|check_hostname\s*=\s*False|"
                r"rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true)"),
     "TLS certificate checking is turned off, allowing man-in-the-middle attacks.",
     "Keep certificate verification on; trust a specific CA instead of disabling checks."),
    (re.compile(r"^\s*DEBUG\s*=\s*True\b|\bapp\.run\(.*debug\s*=\s*True"),
     "Debug mode is on. In production this shows stack traces and settings to "
     "anyone (and Flask's debugger allows running code).",
     "Read it from the environment, e.g. DEBUG = os.getenv('DEBUG') == '1'."),
    (NODE_TLS_RE,
     "Setting NODE_TLS_REJECT_UNAUTHORIZED to 0 turns off TLS certificate checking for the whole Node process.",
     "Remove it; trust a specific CA with NODE_EXTRA_CA_CERTS instead."),
    (CORS_RE,
     'CORS allows every website ("*") to call this API from a browser.',
     "List the exact origins that need access."),
    (re.compile(r"ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]"),
     'ALLOWED_HOSTS = ["*"] disables Django\'s Host header protection.',
     "List your real domain names."),
    (re.compile(r"@csrf_exempt\b|csrf\s*[:=]\s*(False|false)|WTF_CSRF_ENABLED\s*=\s*False"),
     "CSRF protection is turned off for this code.",
     "Keep CSRF on; for APIs use token auth instead of exempting views."),
    (re.compile(r"\b(SESSION|CSRF)_COOKIE_SECURE\s*=\s*False"),
     "Cookies may be sent over plain HTTP, where they can be stolen.",
     "Set the cookie's Secure flag in production."),
]

DANGEROUS_CALLS = [
    (re.compile(r"(?<![\w.])eval\s*\("), "eval()",
     "eval runs any string as code; if any part comes from a user, they can run anything.",
     "Use json.loads / ast.literal_eval (Python) or JSON.parse (JS) to parse data."),
    (re.compile(r"(?<![\w.])exec\s*\((?!\s*\))"), "exec()",
     "exec runs any string as code.",
     "Avoid it; call the function you need directly."),
    (re.compile(r"\bnew\s+Function\s*\("), "new Function()",
     "new Function compiles a string into code, like eval.",
     "Avoid building code from strings."),
    (re.compile(r"\bshell\s*=\s*True\b"), "shell=True",
     "Running a command through the shell allows command injection if any part "
     "of it comes from user input.",
     "Pass a list of arguments without shell=True: subprocess.run(['ls', path])."),
    (re.compile(r"\bos\.(system|popen)\s*\("), "os.system()",
     "os.system runs the command through the shell (command injection risk).",
     "Use subprocess.run with a list of arguments."),
    (re.compile(r"\bchild_process\b.*\bexec(Sync)?\s*\(|\bexecSync\s*\("), "child_process.exec",
     "exec runs the command through a shell (command injection risk).",
     "Use execFile / spawn with an argument array."),
    (re.compile(r"\b(c?pickle|dill|marshal)\.loads?\s*\("), "pickle.load()",
     "Unpickling data runs code chosen by whoever made the data. Never unpickle "
     "anything that came from a user or the network.",
     "Use JSON for data exchange, or sign the data and verify it first."),
    (re.compile(r"\byaml\.(load|load_all)\s*\((?!.*Loader\s*=\s*(yaml\.)?(Safe|Base)Loader)"),
     "yaml.load()", "yaml.load without SafeLoader can build arbitrary Python objects.",
     "Use yaml.safe_load()."),
    (re.compile(r"dangerouslySetInnerHTML"), "dangerouslySetInnerHTML",
     "Inserting raw HTML allows cross-site scripting (XSS) if it contains user input.",
     "Render text normally, or sanitize the HTML with a library like DOMPurify."),
]


def _line_rule_findings(f: FileDiff) -> list[Finding]:
    # Tests disable TLS, run eval, use DEBUG=True all the time on purpose.
    if f.is_deleted or is_test_path(f.path) or is_fixture_path(f.path):
        return []
    if f.path.endswith(DOC_EXTS):
        return []  # docs mention these things without doing them
    out: list[Finding] = []
    in_doc = _docstring_lines([a.text for a in f.added])
    for a, doc in zip(f.added, in_doc):
        if doc or _is_comment(a.text):
            continue
        for rx, msg, fix in INSECURE_SETTINGS:
            hit = rx.search(a.text) if rx in MAY_START_IN_STRING else _code_match(rx, a.text)
            if hit:
                out.append(Finding("risky.insecure-setting", Severity.MEDIUM, f.path, a.number, msg, fix))
                break
        for rx, name, msg, fix in DANGEROUS_CALLS:
            if _code_match(rx, a.text):
                out.append(Finding("risky.dangerous-call", Severity.MEDIUM, f.path, a.number,
                                   f"{name}: {msg}", fix))
                break
    return out


# ------------------------------------------------------------------ the check

def check_risky(files: list[FileDiff]) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    for f in files:
        findings += _auth_findings(f)
        findings += _migration_findings(f)
        findings += _test_findings(f)
        findings += _line_rule_findings(f)
    findings += _no_tests_finding(files)
    return findings, []
