# AgentShield: notes for Claude Code

## What this is
A CLI (`agentshield scan`) that checks a code diff for the mistakes AI coding
tools make before they merge: hallucinated packages, leaked secrets, risky
changes. It outputs a 0-100 risk score plus a concrete fix for each finding.
This is a resume project for a first-year CS + Stats student at Duke.

## BUILD-THEN-LEARN MODE (most important rule)
The owner (Vikhram) wants the whole roadmap built first, then he will study it.
He must still be able to explain every part in an interview, so:
- Build the roadmap steps in order. After EACH step: run the full test suite,
  fix failures, add an entry to DECISIONS.md (choice, alternatives, why), and
  make a git commit with a clear message (one commit per step, so the history
  tells the story).
- Prefer simple, readable code with comments that explain *why*, not clever code.
- When everything is built, write STUDY_GUIDE.md: a walkthrough of the codebase
  in reading order, each concept explained in plain English (diffs, regex,
  entropy, edit distance, CI/GitHub Actions, precision/recall), and 5 likely
  interview questions per step with model answers.
- Afterwards, when asked to quiz him, ask questions one at a time and check his
  answers honestly.

## Architecture
```
agentshield/
  cli.py            argparse entry point, picks output format, exit codes
  diff.py           parse unified diffs -> FileDiff(added lines + line numbers)
  findings.py       Finding dataclass, Severity, risk_score()
  report.py         text / markdown / json renderers
  registry.py       PyPI + npm lookups (injectable fetcher, cached)
  similarity.py     edit distance for typosquat detection
  config.py         .agentshield.toml + inline `agentshield: ignore` comments
  paths.py          is this a test / fixture / source file?
  checks/packages.py  hallucinated / new / typosquat / malware packages
  checks/secrets.py   known key formats + entropy, masked output
  checks/risky.py     auth, migrations, tests, insecure settings, dangerous calls
  data/             popular package lists, import->package name map
tests/              unittest; fake_registry.py so tests never hit the network,
                    helpers.py builds diffs and fake keys at runtime
```
Every check is a function that takes `list[FileDiff]` and returns
`(list[Finding], list[str] notes)`. cli.py runs all checks and merges results.

## Conventions
- Python >= 3.11 (for tomllib; see DECISIONS.md #22), **standard library only** (no pip dependencies; see DECISIONS.md #3).
- Tests: `python3 -m unittest discover -s tests -t . -v`. Every check needs
  tests, including false-positive cases. Network calls go through an
  injectable function and are faked in tests.
- Never report something as definitely wrong when we couldn't verify it;
  add a note instead (DECISIONS.md #5).
- Each finding: stable rule id (e.g. `secret.aws-key`), severity, file, line,
  message (what's wrong), fix (what to do).

## Roadmap (do in order, one step per session)
1. [DONE] Package checker
2. [DONE] Secret scanner (checks/secrets.py): regexes for known key formats (AWS,
   GitHub, OpenAI, Anthropic, Stripe, Slack, Google, private keys, JWTs,
   DB URLs with passwords) + Shannon-entropy check for unknown high-randomness
   strings. Skip obvious placeholders (xxx, your-key-here, example, test
   fixtures). Mask secrets in output (show first 4 chars only).
3. [DONE] Risky-change rules (checks/risky.py): auth/login/permission code changed,
   DB migrations (DROP TABLE, DROP COLUMN), deleted or skipped tests, source
   changed with no test changes, disabled security settings (verify=False,
   DEBUG=True, CORS "*"), dangerous calls (eval, exec, shell=True, pickle.loads).
4. [DONE] Config file `.agentshield.toml` (ignore paths, allowlist packages, thresholds)
   + inline `# agentshield: ignore` comments.
5. GitHub Action (action.yml + workflow) that runs on PRs and posts the
   markdown report as a comment.
6. Benchmark (bench/): collect ~150 real public PRs (include AI-assisted ones),
   run AgentShield, hand-label findings, report precision/recall + scan time.
   These numbers go on the resume. Be honest about false positives.
7. Polish: README with demo GIF, PyPI release, clean commit history.
