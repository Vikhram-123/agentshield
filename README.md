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

Secrets are masked in every report (`AKIA********`).

*Coming next: risky auth/database changes, deleted tests, GitHub Action.*

## Install

```bash
cd agentshield
python3 -m venv .venv && source .venv/bin/activate
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
