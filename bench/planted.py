"""Step 3 of the benchmark: recall, measured by planting known problems.

    python bench/planted.py       # writes bench/planted_results.json

Real PRs rarely contain a leaked key or a hallucinated package, so counting
what AgentShield *misses* in them says little. Instead, each problem below is
written the way it shows up in real code, then inserted into a copy of a real
benchmark PR, next to real added lines in a file of the same language. Recall
= planted problems found with the right rule, on the right line.

"Hard" cases are ones I expect to miss: they show the limits of the design
(for example, the entropy check needs a secret-sounding variable name).
"""

from __future__ import annotations

import csv
import json
import os
import random
import re
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from agentshield.cli import scan  # noqa: E402
from agentshield.config import Config  # noqa: E402
from agentshield.diff import parse_diff  # noqa: E402
from agentshield.paths import is_fixture_path, is_test_path  # noqa: E402
from agentshield.registry import Registry  # noqa: E402

from run import diff_path, load_prs, repo_files  # noqa: E402

SEED = 2026
rng = random.Random(SEED)
B62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def rand(n: int, alphabet: str = B62) -> str:
    return "".join(rng.choice(alphabet) for _ in range(n))


# Names an AI might invent. Checked against the live registry below: any that
# exist get dropped, so a "hallucinated" plant is really missing.
FAKE_PYPI = ["fastapi-jwt-guardian", "django-rest-auth-toolkit", "pandas-schema-validatorx"]
FAKE_NPM = ["react-query-cache-helpers", "csv-parse-sync-utils"]

# (id, expected rule prefix, file kind, lines to add, hard?)
# File kinds: py, js, ts, tsx, env, yml, settings, req, pkgjson, sql, alembic,
# pytest, jstest, pem, go. "{FAKE_PYPI0}" etc. are filled in at runtime.
PLANTS = [
    ("aws-dict", "secret.aws-key", "py", ['    "aws_access_key_id": "AKIA' + rand(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") + '",'], False),
    ("aws-env", "secret.aws-key", "env", ["AWS_SECRET_ACCESS_KEY=" + rand(40)], False),
    ("github-octokit", "secret.github-token", "js", ['const octokit = new Octokit({ auth: "ghp_' + rand(36) + '" });'], False),
    ("openai-client", "secret.openai-key", "py", ['client = OpenAI(api_key="sk-proj-' + rand(48) + '")'], False),
    ("anthropic-ts", "secret.anthropic-key", "ts", ["const anthropic = new Anthropic({ apiKey: 'sk-ant-api03-" + rand(93) + "' });"], False),
    ("stripe-live", "secret.stripe-key", "py", ['stripe.api_key = "sk_live_' + rand(24) + '"'], False),
    ("slack-yaml", "secret.slack-token", "yml", ["  slack_token: xoxb-" + rand(12, "0123456789") + "-" + rand(24)], False),
    ("firebase", "secret.google-api-key", "js", ['  apiKey: "AIza' + rand(35) + '",'], False),
    ("pem-file", "secret.private-key", "pem", ["-----BEGIN " + "RSA PRIVATE KEY-----", rand(64), rand(64), "-----END RSA PRIVATE KEY-----"], False),
    ("db-url", "secret.db-url", "settings", ['DATABASE_URL = "postgresql://app_admin:' + rand(20) + '@prod-db.internal.acme.io:5432/app"'], False),
    ("webhook-secret", "secret.high-entropy", "ts", ['const WEBHOOK_SECRET = "' + rand(32) + '";'], False),
    ("session-env", "secret.high-entropy", "env", ["SESSION_SECRET=" + rand(40)], False),
    ("jwt-header", "secret.jwt", "js", ['  headers: { Authorization: "Bearer eyJ' + rand(30) + ".eyJ" + rand(60) + "." + rand(43) + '" },'], False),
    ("hallucinated-import", "package.", "py", ["from {FAKE_PYPI0_IMPORT} import JWTGuard"], False),
    ("hallucinated-req", "package.", "req", ["{FAKE_PYPI1}==2.1.0"], False),
    ("hallucinated-npm", "package.", "pkgjson", ['    "{FAKE_NPM0}": "^1.2.0",'], False),
    ("hallucinated-require", "package.", "js", ["const { parse } = require('{FAKE_NPM1}');"], False),
    ("typo-req", "package.", "req", ["reqeusts==2.31.0"], False),
    ("typo-import", "package.", "js", ["import axios from 'axois';"], False),
    ("eval-request", "risky.dangerous-call", "py", ['    result = eval(request.args.get("expr"))'], False),
    ("shell-fstring", "risky.dangerous-call", "py", ['    out = subprocess.check_output(f"git log {branch}", shell=True)'], False),
    ("pickle-redis", "risky.dangerous-call", "py", ["    data = pickle.loads(redis_client.get(key))"], False),
    ("yaml-load", "risky.dangerous-call", "py", ["    config = yaml.load(open(path))"], False),
    ("inner-html", "risky.dangerous-call", "tsx", ["      <div dangerouslySetInnerHTML={{ __html: comment.body }} />"], False),
    ("verify-false", "risky.insecure-setting", "py", ["    resp = requests.post(url, json=payload, verify=False)"], False),
    ("debug-true", "risky.insecure-setting", "settings", ["DEBUG = True"], False),
    ("cors-star", "risky.insecure-setting", "py", ['app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)'], False),
    ("tls-node", "risky.insecure-setting", "js", ["    rejectUnauthorized: false,"], False),
    ("drop-column", "risky.destructive-migration", "sql", ["ALTER TABLE users DROP COLUMN legacy_token;"], False),
    ("alembic-drop", "risky.destructive-migration", "alembic", ["def upgrade():", '    op.drop_table("audit_log")'], False),
    ("pytest-skip", "risky.test-skipped", "pytest", ['@pytest.mark.skip(reason="flaky on CI")'], False),
    ("it-only", "risky.test-skipped", "jstest", ["  it.only('handles refunds', async () => {"], False),
    # --- hard cases: expected misses, kept to show the design's limits
    ("hard-unnamed-secret", "secret.", "py", ['x = "' + rand(32) + '"'], True),
    ("hard-custom-format", "secret.", "py", ['ACME_KEY = "acme_live_' + rand(28) + '"'], True),
    ("hard-short-password", "secret.", "py", ['DB_PASSWORD = "Summer2024!"'], True),
    ("hard-aliased-exec", "risky.dangerous-call", "js", ["  cp.exec(`convert ${file} out.png`);"], True),
    ("hard-delete-all", "risky.destructive-migration", "sql", ["DELETE FROM sessions;"], True),
    ("hard-go-module", "package.", "go", ['\t"github.com/acme-labs/fastjwt-guard"'], True),
]

KIND_EXTS = {"py": (".py",), "js": (".js", ".mjs", ".cjs", ".jsx"), "ts": (".ts",),
             "tsx": (".tsx", ".jsx"), "go": (".go",), "yml": (".yml", ".yaml")}
NEW_PATHS = {  # where to put the plant if the PR has no file of that kind
    "py": "app/service.py", "js": "src/client.js", "ts": "src/webhooks.ts", "tsx": "src/Comment.tsx",
    "env": ".env.production", "yml": "deploy/config.yml", "settings": "config/settings.py",
    "req": "requirements.txt", "pkgjson": "package.json", "sql": "db/migrations/0042_cleanup.sql",
    "alembic": "alembic/versions/9f3c_cleanup.py", "pytest": "tests/test_billing.py",
    "jstest": "src/billing.test.ts", "pem": "deploy/server.pem", "go": "internal/auth/jwt.go",
}


def exists(ecosystem: str, name: str) -> bool:
    url = (f"https://pypi.org/pypi/{name}/json" if ecosystem == "pypi"
           else f"https://registry.npmjs.org/{name}")
    try:
        urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "agentshield-bench"}),
                               timeout=10)
        return True
    except urllib.error.HTTPError as e:
        return e.code != 404


def plant(diff: str, kind: str, lines: list[str]) -> tuple[str, str, bool]:
    """Insert `lines` as added lines into a matching file of `diff`.

    Returns (new diff, path of the file that got the plant, whether that file
    was already part of the PR; if not, the plant arrives as a new file).
    """
    blocks = re.split(r"(?m)^(?=diff --git )", diff)
    exts = KIND_EXTS.get(kind)
    wants_test = kind in ("pytest", "jstest")
    candidates = []
    for i, block in enumerate(blocks):
        m = re.match(r"diff --git a/(\S+) b/(\S+)", block)
        if not m or "\n+++ /dev/null" in block or not exts:
            continue
        path = m.group(2)
        # A plant must land where that problem could really be: app code for
        # app problems (not tests, fixtures or lockfiles).
        if (not path.endswith(exts) or os.path.basename(path) in LOCKFILES
                or (is_test_path(path) or is_fixture_path(path)) != wants_test):
            continue
        if _code_slots(blocks[i].split("\n")):
            candidates.append((i, path))
    if candidates:
        i, path = rng.choice(candidates)
        body = blocks[i].split("\n")
        at = rng.choice(_code_slots(body))
        body[at:at] = ["+" + ln for ln in lines]
        blocks[i] = "\n".join(body)
        return "".join(blocks), path, True
    path = NEW_PATHS[kind]
    new = (f"diff --git a/{path} b/{path}\nnew file mode 100644\n--- /dev/null\n+++ b/{path}\n"
           f"@@ -0,0 +1,{len(lines)} @@\n" + "\n".join("+" + ln for ln in lines) + "\n")
    return diff.rstrip("\n") + "\n" + new, path, False


LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock"}


def _code_slots(body: list[str]) -> list[int]:
    """Positions just before an added line where new code can go: not inside a
    multi-line string or docstring (code planted there is just text, and the
    first version of this harness did exactly that by accident)."""
    slots, inside = [], False
    for j, ln in enumerate(body):
        if ln.startswith("@@"):
            inside = False  # each hunk restarts our view of the file
            continue
        if ln[:1] not in ("+", " ") or ln.startswith("+++"):
            continue
        if ln.startswith("+") and not inside:
            slots.append(j)
        text = ln[1:]
        if (text.count('"""') + text.count("\'\'\'") + text.count("`")) % 2 == 1:
            inside = not inside
    return slots


def main() -> int:
    fake_pypi = [n for n in FAKE_PYPI if not exists("pypi", n)]
    fake_npm = [n for n in FAKE_NPM if not exists("npm", n)]
    if len(fake_pypi) < 2 or len(fake_npm) < 2:
        print(f"Not enough unregistered names: {fake_pypi} {fake_npm}", file=sys.stderr)
        return 1
    # Python imports use underscores: "fastapi-jwt-guardian" is imported as
    # fastapi_jwt_guardian (a hyphen would be a syntax error, and a bug in this harness).
    fills = {"{FAKE_PYPI0_IMPORT}": fake_pypi[0].replace("-", "_"),
             "{FAKE_PYPI0}": fake_pypi[0], "{FAKE_PYPI1}": fake_pypi[1],
             "{FAKE_NPM0}": fake_npm[0], "{FAKE_NPM1}": fake_npm[1]}

    prs = load_prs("test")  # plant into held-out PRs
    changed = {}  # PR id -> paths of files it adds lines to
    for p in prs:
        with open(diff_path(p), encoding="utf-8", errors="replace") as fh:
            changed[p["id"]] = [f.path for f in parse_diff(fh.read()) if f.added]
    results = []
    for pid, expected, kind, lines, hard in PLANTS:
        lines = [_fill(ln, fills) for ln in lines]
        # Prefer a PR that already changes a file of this language, so the plant
        # sits among real code (the harder, more realistic case).
        exts = KIND_EXTS.get(kind)
        wants_test = kind in ("pytest", "jstest")
        fitting = [p for p in prs if exts and any(
            e.endswith(exts) and (is_test_path(e) or is_fixture_path(e)) == wants_test
            and os.path.basename(e) not in LOCKFILES for e in changed[p["id"]])]
        pr = rng.choice(fitting or prs)
        with open(diff_path(pr), encoding="utf-8", errors="replace") as fh:
            diff = fh.read()
        new_diff, path, in_existing = plant(diff, kind, lines)
        findings, _, _ = scan(new_diff, Config(), Registry(), repo_root="/nonexistent",
                              repo_files=repo_files(pr) or [])
        planted_text = {ln.strip() for ln in lines}
        hits = [f for f in findings if f.file == path and f.rule.startswith(expected)]
        # The finding must point at a planted line (not something already in the PR).
        hits = [f for f in hits if _line_text(new_diff, path, f.line) in planted_text]
        results.append({"id": pid, "expected": expected, "hard": hard, "pr": pr["id"],
                        "file": path, "in_existing_file": in_existing, "found": bool(hits),
                        "rule": hits[0].rule if hits else None,
                        "severity": hits[0].severity.value if hits else None})
        print(f"{'HIT ' if hits else 'MISS'} {pid:22} {expected:28} in {pr['id']}:{path}", file=sys.stderr)

    with open(os.path.join(HERE, "planted_results.json"), "w") as fh:
        json.dump({"seed": SEED, "results": results}, fh, indent=1)
    return 0


def _fill(line: str, fills: dict[str, str]) -> str:
    for k, v in fills.items():
        line = line.replace(k, v)
    return line


def _line_text(diff: str, path: str, line: int | None) -> str | None:
    from agentshield.diff import parse_diff
    if line is None:
        return None
    for f in parse_diff(diff):
        if f.path == path:
            for a in f.added:
                if a.number == line:
                    return a.text.strip()
    return None


if __name__ == "__main__":
    sys.exit(main())
