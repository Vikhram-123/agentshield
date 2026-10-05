# Benchmark results

Labels were assigned by Claude and still need a human spot-check (see `LABELING.md`). Every label has a one-line reason in `labels.csv`.

## Held-out test set (the real numbers)

143 public pull requests created in August 2026, collected **after** all tuning was finished and scanned once with the frozen tool. Diff size: median 177 lines, max 2708.

**Precision: 18/25 = 72% (95% CI 52%-86%)**

| Rule | Findings | TP | FP | Precision (95% CI) |
|---|---|---|---|---|
| `risky.no-tests` | 19 | 15 | 4 | 79% (57%-91%) |
| `package.not-found` | 2 | 0 | 2 | 0% (0%-66%) |
| `risky.test-deleted` | 2 | 2 | 0 | 100% (34%-100%) |
| `risky.auth-change` | 1 | 1 | 0 | 100% (21%-100%) |
| `risky.destructive-migration` | 1 | 0 | 1 | 0% (0%-79%) |

| Severity | TP | FP | Precision |
|---|---|---|---|
| high | 0 | 1 | 0% |
| medium | 2 | 2 | 50% |
| low | 16 | 4 | 80% |

**After the fact:** the held-out set exposed 3 more bugs (English in a JS comment read as an import, `import paho` → `paho-mqtt` missing from the name map, a `test-harness/` folder not seen as tests). Fixing them removed exactly those 3 false positives and nothing else: 18/22 = 82% (95% CI 61%-93%) on the same PRs. That number is no longer held-out, so the 72% above stays the headline.

### Findings by group

| Group | PRs | PRs with ≥1 finding | Findings per 1,000 diff lines |
|---|---|---|---|
| ai-claude-code | 40 | 8 | 0.4 |
| ai-copilot-agent | 25 | 3 | 0.2 |
| ai-cursor | 10 | 1 | 0.2 |
| ai-devin | 15 | 3 | 0.4 |
| no-ai-marker | 53 | 8 | 0.5 |

Groups differ in repo size, language and PR size, so this describes the sample; it is not evidence that AI-written code is riskier.

## Recall (planted problems)

Real PRs rarely contain a leaked key or a hallucinated package, so recall is measured by planting known problems, written the way they appear in real code, into copies of test-set PRs (`planted.py`).

**In-scope problems found: 32/32 = 100% (95% CI 89%-100%).**

20 of the 32 in-scope plants landed inside a file the PR already changed; the rest arrived as a new file (the PR had no file of that language), which is the easier case.

Caveat: the same person wrote the rules and the plants, so this is an upper bound on recall, not an unbiased estimate. It does show the rules survive real surroundings (path filters, test-file handling, other findings).

Deliberately out-of-scope cases: 0/6 found (expected: these show the design's limits).

| Planted problem | Expected rule | Found? |
|---|---|---|
| aws-dict | `secret.aws-key` | yes |
| aws-env | `secret.aws-key` | yes |
| github-octokit | `secret.github-token` | yes |
| openai-client | `secret.openai-key` | yes |
| anthropic-ts | `secret.anthropic-key` | yes |
| stripe-live | `secret.stripe-key` | yes |
| slack-yaml | `secret.slack-token` | yes |
| firebase | `secret.google-api-key` | yes |
| pem-file | `secret.private-key` | yes |
| db-url | `secret.db-url` | yes |
| webhook-secret | `secret.high-entropy` | yes |
| session-env | `secret.high-entropy` | yes |
| jwt-header | `secret.jwt` | yes |
| hallucinated-import | `package.` | yes |
| hallucinated-req | `package.` | yes |
| hallucinated-npm | `package.` | yes |
| hallucinated-require | `package.` | yes |
| typo-req | `package.` | yes |
| typo-import | `package.` | yes |
| eval-request | `risky.dangerous-call` | yes |
| shell-fstring | `risky.dangerous-call` | yes |
| pickle-redis | `risky.dangerous-call` | yes |
| yaml-load | `risky.dangerous-call` | yes |
| inner-html | `risky.dangerous-call` | yes |
| verify-false | `risky.insecure-setting` | yes |
| debug-true | `risky.insecure-setting` | yes |
| cors-star | `risky.insecure-setting` | yes |
| tls-node | `risky.insecure-setting` | yes |
| drop-column | `risky.destructive-migration` | yes |
| alembic-drop | `risky.destructive-migration` | yes |
| pytest-skip | `risky.test-skipped` | yes |
| it-only | `risky.test-skipped` | yes |
| hard-unnamed-secret (out of scope) | `secret.` | **no** |
| hard-custom-format (out of scope) | `secret.` | **no** |
| hard-short-password (out of scope) | `secret.` | **no** |
| hard-aliased-exec (out of scope) | `risky.dangerous-call` | **no** |
| hard-delete-all (out of scope) | `risky.destructive-migration` | **no** |
| hard-go-module (out of scope) | `package.` | **no** |

## Speed

Per PR, wall-clock, including live PyPI/npm lookups: median 0.01s, 95th percentile 0.42s, max 3.26s.
Without the network (`--offline`): median 6ms, max 208ms. Nearly all the time is registry lookups, and it varies with network conditions.

## Development set (optimistic: the tool was fixed using it)

142 PRs from September 2026. Labeling the first run exposed false positives (monorepo workspace packages, path aliases, `bun:` imports, conditional test skips, renamed tests, docs). Each was fixed with a regression test, then the set was re-run.

### Before fixes

**Precision: 14/39 = 36% (95% CI 23%-52%)**

| Rule | Findings | TP | FP | Precision (95% CI) |
|---|---|---|---|---|
| `package.not-found` | 13 | 0 | 13 | 0% (0%-23%) |
| `risky.no-tests` | 13 | 11 | 2 | 85% (58%-96%) |
| `risky.test-skipped` | 4 | 0 | 4 | 0% (0%-49%) |
| `risky.test-deleted` | 3 | 0 | 3 | 0% (0%-56%) |
| `risky.dangerous-call` | 2 | 2 | 0 | 100% (34%-100%) |
| `package.malware-removed` | 1 | 0 | 1 | 0% (0%-79%) |
| `package.new` | 1 | 0 | 1 | 0% (0%-79%) |
| `risky.auth-change` | 1 | 1 | 0 | 100% (21%-100%) |
| `risky.auth-guard-removed` | 1 | 0 | 1 | 0% (0%-79%) |

| Severity | TP | FP | Precision |
|---|---|---|---|
| high | 0 | 2 | 0% |
| medium | 2 | 21 | 9% |
| low | 12 | 2 | 86% |

### After fixes

**Precision: 14/19 = 74% (95% CI 51%-88%)**

| Rule | Findings | TP | FP | Precision (95% CI) |
|---|---|---|---|---|
| `risky.no-tests` | 13 | 11 | 2 | 85% (58%-96%) |
| `package.not-found` | 2 | 0 | 2 | 0% (0%-66%) |
| `risky.dangerous-call` | 2 | 2 | 0 | 100% (34%-100%) |
| `package.new` | 1 | 0 | 1 | 0% (0%-79%) |
| `risky.auth-change` | 1 | 1 | 0 | 100% (21%-100%) |

| Severity | TP | FP | Precision |
|---|---|---|---|
| high | 0 | 0 | - |
| medium | 2 | 3 | 40% |
| low | 12 | 2 | 86% |
