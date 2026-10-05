# 🛡️ AgentShield

**Catch the mistakes AI coding tools make before they merge.**

AI assistants sometimes import packages that don't exist. Attackers watch for
those hallucinated names, register them on PyPI/npm and fill them with
malware ("slopsquatting"). AgentShield scans a code change and flags:

| Check | Example | Severity |
|---|---|---|
| Package doesn't exist | `flask-auth-helper` in requirements.txt | HIGH |
| Look-alike of a popular package | `reqeusts`, `lodahs` | MEDIUM, or HIGH if brand new |
| Brand-new package (< 30 days old) | first published 5 days ago | MEDIUM |
| Removed by npm for malware | `0.0.1-security` stub | HIGH |
| Unknown import | `import langchain_memory_tools` | MEDIUM |
| Leaked API key (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, private keys, DB URLs) | `AKIA...` in `config.py` | HIGH |
| Random-looking value in a secret-named variable | `api_key = "q8Zr..."` | MEDIUM |

| Destructive migration | `DROP TABLE`, `op.drop_column`, `RemoveField` (not in `downgrade()`) | HIGH |
| Access check removed | `@login_required` deleted from a view | MEDIUM |
| Test deleted, skipped or `.only`'d | `@pytest.mark.skip`, `it.only(` | MEDIUM |
| Security setting turned off | `verify=False`, `DEBUG = True`, CORS `"*"`, `@csrf_exempt` | MEDIUM |
| Dangerous call | `eval`, `exec`, `shell=True`, `pickle.loads`, `yaml.load` | MEDIUM |
| Auth code touched / source changed without tests | `app/auth/session.py` | LOW |

Secrets are masked in every report (`AKIA********`).



## Install

```bash
cd agentshield
python3 -m venv .venv   # Python 3.11+ && source .venv/bin/activate
pip install -e .
```

## Use

```bash
agentshield scan                     # everything changed since your last commit
agentshield scan --base main         # what this branch adds on top of main
agentshield scan --staged            # only what you've staged
agentshield scan --diff pr.diff      # any diff file (or "-" for stdin)
agentshield scan --format markdown   # for PR comments (also: json)
agentshield scan --offline           # no network: typo checks only
agentshield scan --fail-on medium    # exit code 1 on medium+ (for CI)
```

## GitHub Action

Scan every pull request and post the report as a comment:

```yaml
# .github/workflows/agentshield.yml
name: agentshield
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: OWNER/agentshield@v1   # replace OWNER once published
        with:
          fail-on: high              # high | medium | low | never
```

The comment is edited in place on each push (no comment spam), and the
report is always in the job summary too. PRs from forks get a read-only
token, so for those the report is only in the job summary. AgentShield
deliberately does not use `pull_request_target`, which would hand fork code a
write token.

## Configure

Optional. Put a `.agentshield.toml` in the repo root:

```toml
fail_on = "medium"                     # high | medium | low | never
fail_score = 60                        # also fail if the risk score reaches 60
ignore_paths = ["vendor/", "*.min.js"]
ignore_rules = ["risky.no-tests"]      # or a whole family: "secret"
allow_packages = ["acme-internal-sdk", "@acme/*"]
new_package_days = 30
```

Or silence one line in place:

```python
result = eval(expr)  # agentshield: ignore[risky.dangerous-call]
```

Hidden findings are always counted in the report's notes, so nothing is
suppressed silently. Unknown settings are an error, not ignored.

Try it on the sample "AI-written" pull request:

```bash
agentshield scan --diff tests/fixtures/ai_pr.diff
```

## How it works

```
git diff ─▶ diff.py ─▶ checks/packages.py ─▶ registry.py ─▶ report.py
            added      extract deps,         PyPI / npm      text, markdown,
            lines +    filter stdlib &       exists? age?    json + risk score
            line #s    local modules,        (parallel,
                       typo distance         cached)
```

Standard library only: no dependencies to install, nothing extra to trust.

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

Tests use a fake registry (`tests/fake_registry.py`), so they run offline and
always give the same result.
