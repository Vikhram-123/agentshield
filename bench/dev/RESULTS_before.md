# Benchmark results

## Dataset

142 real public pull requests created in September 2026, chosen mechanically (see `collect.py`). Diff size: median 232 lines, max 2916.

| Group | PRs |
|---|---|
| ai-claude-code | 40 |
| ai-copilot-agent | 25 |
| ai-cursor | 10 |
| ai-devin | 15 |
| no-ai-marker | 52 |

## Precision (are the findings right?)

**Overall: 14/39 = 36% (95% CI 23%-52%)**.

| Rule | Findings | TP | FP | Precision (95% CI) |
|---|---|---|---|---|
| `risky.no-tests` | 13 | 11 | 2 | 85% (58%-96%) |
| `package.not-found` | 13 | 0 | 13 | 0% (0%-23%) |
| `risky.test-skipped` | 4 | 0 | 4 | 0% (0%-49%) |
| `risky.test-deleted` | 3 | 0 | 3 | 0% (0%-56%) |
| `risky.dangerous-call` | 2 | 2 | 0 | 100% (34%-100%) |
| `risky.auth-change` | 1 | 1 | 0 | 100% (21%-100%) |
| `package.new` | 1 | 0 | 1 | 0% (0%-79%) |
| `package.malware-removed` | 1 | 0 | 1 | 0% (0%-79%) |
| `risky.auth-guard-removed` | 1 | 0 | 1 | 0% (0%-79%) |

| Severity | TP | FP | Precision |
|---|---|---|---|
| high | 0 | 2 | 0% |
| medium | 2 | 21 | 9% |
| low | 12 | 2 | 86% |

## Findings per PR, by group

| Group | PRs | PRs with ≥1 finding | Findings per 1,000 diff lines |
|---|---|---|---|
| ai-claude-code | 40 | 12 | 0.5 |
| ai-copilot-agent | 25 | 7 | 1.0 |
| ai-cursor | 10 | 3 | 0.5 |
| ai-devin | 15 | 1 | 0.1 |
| no-ai-marker | 52 | 6 | 0.7 |

Groups differ in repo size, language and PR size, so this is a description of the sample, not evidence that AI code is riskier.

## Speed

Wall-clock per PR including live PyPI/npm lookups: median 0.01s, 95th percentile 0.53s, max 9.06s.

Without the network (`--offline`): median 7ms, max 458ms. Almost all the time is registry lookups.

