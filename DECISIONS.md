# Design decisions

Why AgentShield is built the way it is. **Read this before interviews.**
Each entry: the choice, the alternatives, and why.

### 1. CLI first, GitHub Action later
- *Alternatives:* start as a GitHub Action or a VS Code extension.
- *Why:* a CLI runs on my laptop, so testing is instant. An Action is just a
  thin wrapper that calls the CLI, so nothing is wasted.

### 2. Scan the diff, not the whole repo
- *Why:* reviewers care about what *this change* introduces. It's also fast,
  and every finding points to the exact line that was added.
- *How:* the `@@ -a,b +c,d @@` hunk header gives the starting line in the new
  file. Counting context and added lines from there gives real line numbers.

### 3. Standard library only (no pip dependencies)
- *Alternatives:* `requests`, `rich`, `click`.
- *Why:* a security tool that pulls in extra packages adds the exact risk it
  checks for. It also installs instantly in CI.

### 4. Manifest = HIGH, import = MEDIUM
- *Why:* `requirements.txt` / `package.json` are what actually get installed.
  An import name can legitimately differ from its package name
  (`import yaml` installs `pyyaml`), so "not found" on an import is less certain.
  A mapping file (`data/import_names.txt`) handles the common cases.

### 5. Never say "doesn't exist" unless the registry said 404
- *Why:* if the network fails, we report a note ("couldn't verify"), not a
  finding. A false "hallucinated!" alarm would destroy trust in the tool.

### 6. Typosquat detection with edit distance + a popular-packages list
- *Algorithm:* optimal string alignment distance (insert, delete, substitute,
  swap neighbours) via dynamic programming, O(n·m).
- *Thresholds:* names under 4 chars are never flagged; up to 6 chars allows 1
  edit; longer allows 2. Short names collide by accident (`six` vs `sip`).
- *Severity:* look-alike = MEDIUM; look-alike **and** under 30 days old = HIGH,
  because that combination is what real attacks look like.

### 7. Popular packages skip the network
- *Why:* we know `requests` exists. Skipping it makes scans faster and means
  fewer requests to PyPI/npm.

### 8. Lookups run in parallel and are cached
- *Why:* a PR can add 20 packages. 8 threads and one lookup per name keeps
  scans to about a second.

### 9. Risk score = capped sum of severity weights
- HIGH 40, MEDIUM 15, LOW 5, capped at 100. Simple, explainable, and easy to
  tune later once there's benchmark data.

### 10. Live check of step 1 against real PyPI/npm
- *What I ran:* the sample PR (`tests/fixtures/ai_pr.diff`) with no fake
  registry, plus a "control" diff of real but less-popular packages
  (`django-ninja`, `zope.interface`, `@tanstack/react-query`, `bs4`, ...).
- *Result:* every verdict matched a manual `curl` of the registry API, and
  `lodahs` turned out to be a real npm malware takedown. The control diff
  found one false positive: `import ruamel.yaml` was looked up as `ruamel`,
  a namespace rather than a package. I fixed it with a mapping line plus a regression test.
- *Lesson:* fake registries prove the logic. Only real data shows which import
  names don't match their package names.

### 11. Python 3.10 is a hard minimum
- `sys.stdlib_module_names` (the list of standard-library modules) only exists
  from 3.10. On 3.9 the stdlib filter is silently empty and `import os` gets
  flagged. macOS ships 3.9, so `pyproject.toml`'s `requires-python = ">=3.10"`
  matters: pip refuses to install on 3.9 instead of producing junk.

## Step 2: secret scanner (`checks/secrets.py`)

### 12. Two layers: known formats first, entropy second
- *Known formats:* one regex per provider prefix (`AKIA`, `ghp_`, `sk-ant-`,
  `sk_live_`, `xoxb-`, `AIza`, `eyJ...`, `-----BEGIN ... PRIVATE KEY-----`,
  `postgres://user:pass@host`). A prefix match is near-certain, so these are
  HIGH (MEDIUM for Google keys and JWTs; see #15).
- *Entropy:* for unknown formats, measure how random a value is (Shannon
  entropy, bits per character: `-Σ p·log2(p)`).
- *Alternatives:* entropy alone (what early tools like truffleHog did) is very
  noisy; regex alone misses custom keys. Using both, with regex first, gives
  precise named findings and a fallback.
- *Order matters:* `sk-ant-` (Anthropic) is checked before `sk-` (OpenAI), and
  once a span is reported nothing else can report it, so one key = one finding.

### 13. Entropy only runs on secret-named variables
- *Rule:* the value must be assigned to a name containing secret/token/password/
  api_key/..., be ≥ 16 chars, contain a letter **and** a digit, not be a URL or
  path, and score ≥ 3.5 bits/char.
- *Why not every string?* Hashes, UUIDs, base64 images and lockfile checksums
  are random too. Measured: a random 20-char key scores 3.9, but so does
  `app.settings.SECRET_KEY` (4.0). Entropy can't separate them; the
  letter+digit rule and the variable name can.
- *Trade-off:* a key assigned to `x = "..."` is missed. I chose precision over
  recall; the benchmark (step 6) will show whether that was right.
- Unquoted `NAME=value` only counts in `.env`/YAML/ini files; in code it's
  usually a function call, not a literal.

### 14. Placeholders, test files, lockfiles
- *Placeholders skipped:* values containing `xxx`, `your`, `example`,
  `changeme`, `<...>`, `${...}`, a repeated single character, and default dev
  passwords in DB URLs (`postgres:postgres@`, or host `localhost`). The AWS
  docs key `AKIAIOSFODNN7EXAMPLE` is skipped because it contains "example".
- *Safe formats:* Stripe `sk_test_`/`pk_live_` keys can't move money or are
  meant to be public.
- *Test/fixture/example files:* known-format hits are **downgraded to LOW**,
  not skipped (real keys do leak in tests), and the entropy layer is off there.
  A note tells the reviewer.
- *Lockfiles, `.min.js`, `.map`, `.svg`:* skipped entirely (full of checksums).

### 15. Severity choices
- HIGH for keys that give direct access (cloud, payments, source control, LLM
  APIs: someone can run up your bill).
- MEDIUM for Google API keys (Firebase/browser keys are often public by design),
  JWTs (often short-lived), Slack webhooks (can only post) and entropy guesses.

### 16. Mask secrets in output, and never put real-looking keys in our own repo
- The report shows the first 4 chars + `********` (nothing for secrets under
  12 chars like passwords, since 4 chars of a short password leaks too much). A
  security tool's report gets pasted into PR comments, so it must not leak again.
- Tests build fake keys at runtime (`"AKIA" + fake_secret(16)`), so the source
  never contains a key-shaped string. GitHub push protection would block it,
  and AgentShield would flag its own tests.

### 17. Measured, not guessed
- **Precision:** treated the whole Python 3.12 stdlib (1,093 files, 445k lines)
  as one big added diff: **0 findings**.
- **Recall:** gitleaks' sample repos: 4/4 planted AWS keys found. Tiny sample;
  step 6 gives the real number.
- **Speed:** the first version took 7.9s on the stdlib. Profiling showed the
  assignment regex was 90% of it: an unanchored `[\w.-]*` retried at every
  character. Anchoring the name plus a cheap keyword pre-check → 3.3s
  (≈7µs/line; a big PR is milliseconds).

## Step 3: risky-change rules (`checks/risky.py`)

### 18. "A human should look" is the main severity
- Nothing in this check is wrong for certain: dropping a column or calling
  `eval` can be deliberate. So most rules are MEDIUM (look at this) or LOW
  (FYI). Only destructive migrations are HIGH, because data loss can't be undone.
- *Alternative:* block on all of them. That would train people to ignore the
  tool, and a security tool that gets ignored is worse than none.

### 19. Removed lines now carry a position
- `FileDiff.removed` used to be plain strings. To say "an auth check was
  removed **here**", each removed line now records the new-file line it sat
  above (the same idea GitHub uses to place comments on deletions).
- Deleted files are now passed to the checks (the CLI used to drop them),
  because "a whole test file was deleted" is exactly what we want to see.

### 20. Rule-by-rule false-positive guards
| Rule | Guard against noise |
|---|---|
| auth guard removed | not if the same line (ignoring whitespace) was re-added: that's a move |
| auth file changed | path words like `auth`, `login`, `permission`; **not** `author` or `session` (usually a DB session) |
| destructive migration | skipped inside `downgrade()` / `exports.down` / `*.down.sql`: dropping in the undo step just reverses a create |
| destructive migration | SQL needs `DROP TABLE`/`TRUNCATE TABLE` (not English "truncate"); Rails `drop_table` only at line start (not `def drop_table`) |
| test deleted | not if a test with the same name was added back (edited, not removed) |
| test skipped | unconditional skips and `.only` only; `skipIf(platform)` is legitimate |
| no tests | only when ≥ 10 non-blank source lines were added and *no* test file changed |
| insecure setting / dangerous call | not in tests, fixtures or docs; not on comment lines; `model.eval()`, `ast.literal_eval`, `yaml.load(..., Loader=SafeLoader)` and nodemailer's `secure: false` don't count |
- Each guard has a test in `tests/test_risky.py` (`test_safe_lookalikes`,
  `test_downgrade_reversals_are_normal`, ...).
- Regexes use `(?<![\w.])eval\(` so a *method* called eval (PyTorch's
  `model.eval()`) doesn't match: the lookbehind forbids a dot or letter before it.

### 21. Unreadable input is an error, not "CLEAN"
- While spot-checking real PRs, one download was an HTML page instead of a
  diff, and AgentShield said "Risk 0/100 (CLEAN)". Now non-empty input that
  contains no diff exits with code 2 and an error. An empty diff is still fine
  (nothing changed = nothing to report).

## Step 4: configuration (`config.py`)

### 22. Python 3.11 minimum, for `tomllib`
- The config file is TOML (the format `pyproject.toml` uses). The standard
  library can read TOML only from 3.11 (`tomllib`).
- *Alternatives:* write a mini TOML parser for 3.10 (more code to test, and
  it would be subtly wrong), or use JSON/INI for the config (worse to edit by
  hand: no comments in JSON).
- *Why it's fine:* Python 3.10 reaches end-of-life in October 2026, and CI
  runners default to 3.12. Tested on real 3.11 and 3.12 interpreters.
  (This supersedes the 3.10 minimum in #11.)

### 23. Two escape hatches, at two scopes
- `.agentshield.toml` for project-wide policy (`ignore_paths`, `ignore_rules`,
  `allow_packages`, `fail_on`, `fail_score`, `new_package_days`). It lives in
  the repo, so changing policy goes through code review.
- `# agentshield: ignore[rule]` on a single line for one-off exceptions, next
  to the code, where a reviewer sees it. A bare `agentshield: ignore`
  silences every rule on that line.
- *Why both:* without a cheap way to silence a false positive, people
  disable the whole tool. A tool that can be tuned stays switched on.

### 24. Suppression is never silent
- Every hidden finding is counted in a note ("2 finding(s) hidden by inline
  comments", "3 file(s) skipped by ignore_paths"), so a reviewer can tell when
  someone is hiding things.
- Unknown keys are errors (exit 2): `ignore_path` (missing "s") silently doing
  nothing would be the worst kind of bug in a security tool.

### 25. Matching rules
- Rules: `"secret"` or `"secret.*"` = every secret rule; `"secret.jwt"` = one.
  A prefix must be a whole segment, so `"secret"` doesn't match `"secretive.x"`.
- Paths: `"vendor/"` = that folder at any depth; anything else is a glob
  (`fnmatch`) tried against the full path and the file name.
- Packages: names are PEP 503-normalized and globs work, so `"@acme/*"`
  allows a whole private npm scope. Allowed packages skip the network too.
- CLI flags beat the config file (`--fail-on high` overrides `fail_on`), and
  `--fail-on never` also disables `fail_score`.

### 26. Dogfooding: running AgentShield on its own code
- Scanning this repo's own history found **21 false positives**, all from
  rules matching *text about* risky code rather than risky code: messages
  like `"never use eval()"`, a docstring listing `DROP TABLE`, a README table.
  It also found that one test had a literal key-shaped string, breaking #16.
- *Fix:* a rule now only fires when its match **starts in code**, not inside a
  quoted string (`_in_string`) or a multi-line docstring (`_docstring_lines`).
  Exceptions are rules where the evidence *is* a string: SQL in
  `op.execute("DROP TABLE x")`, the CORS header name, `os.environ["NODE_TLS_..."]`.
  Docs (`.md`, `.rst`) are skipped by the migration rule too.
- Result: 21 → 0 on our own code. The string check is a per-line heuristic
  (an apostrophe in a trailing comment can confuse it), which is acceptable
  because its failure mode is staying quiet, not crying wolf.

## Step 5: GitHub Action (`action.yml`, `github_comment.py`)

### 27. Composite action that installs from its own folder
- *Alternatives:* a Docker action (slow: builds an image every run) or a
  JavaScript action (a second language and a `node_modules` to audit).
- *Why composite:* it's just shell steps. `pip install "$GITHUB_ACTION_PATH"`
  installs the exact code at the action's tag, with no PyPI download, and
  since there are no dependencies (#3) that takes about a second.

### 28. What gets compared
- `git diff origin/<base>...HEAD`: the three dots mean "since the branch split
  off base", so commits that landed on main meanwhile don't show up as the
  PR's changes.
- That needs history. `actions/checkout` clones one commit by default, so
  git says "no merge base". The action detects a shallow clone and fetches
  the history itself (`--unshallow`), with a notice. Users don't have to
  know about `fetch-depth: 0`, though it's faster.

### 29. One comment, edited in place
- An invisible HTML marker (`<!-- agentshield-report -->`) identifies our
  comment. Each run looks for it (paging through comments) and edits it
  (PATCH) instead of posting a new one (POST), so 10 pushes = 1 comment.
- The comment code is Python with an injectable `request` function, the same
  pattern as the registry fetcher (#5), so the tests use a fake GitHub API.

### 30. Security of the action itself
- **`pull_request`, not `pull_request_target`.** `pull_request_target` runs with
  a write token even for PRs from forks, and checking out fork code in that
  context is a well-known way to get repos hijacked. The cost: fork PRs get a
  read-only token and can't be commented on, so we fall back to the job
  summary with a warning, never a failure.
- **Inputs go through `env:`, never `${{ inputs.x }}` inside `run:`.**
  GitHub pastes `${{ }}` into the script text *before* bash runs, so a crafted
  input could inject shell commands. Environment variables are just data.
- **Minimal permissions:** `contents: read`, `pull-requests: write`.

### 31. Exit codes are kept until the end
- The scan step runs with `set +e` and saves the exit code, so the report is
  still published and commented when there are findings. The last step then
  fails the check (exit 1 for findings, and also for errors: exit 2 must
  never look like a pass).

### 32. How it was tested without pushing to GitHub
- `actionlint` (the standard workflow linter) on the workflows, plus
  `shellcheck` on every `run:` script extracted from `action.yml`.
- An end-to-end simulation: a bare "origin" repo, a PR branch with a leaked
  key, a typosquat and `shell=True`, the action's four steps run with
  GitHub's environment variables set, and a local fake GitHub API server.
  Verified: comment created, a second run *updated* it, the check failed, and
  a shallow single-branch clone still worked.
- Not yet verified on real GitHub (needs the repo to be pushed).

## Step 6: benchmark (`bench/`)

Full numbers: `bench/RESULTS.md`. Headline (held-out set, frozen tool):
**precision 72% (18/25, 95% CI 52–86%)**, **recall 32/32 on planted in-scope
problems (upper bound)**, median scan ~10 ms plus network.

### 33. Mechanical PR selection
- GitHub search for each AI tool's marker (Claude Code footer, Copilot coding
  agent, Devin, Cursor co-author) in a fixed date window, newest first, one PR
  per repo; plus the newest PRs from 30 popular projects with no AI marker.
  Diffs over 3,000 lines are skipped (and counted).
- *Why:* if I picked PRs by hand I'd (unconsciously) pick ones the tool does
  well on. A rule that's written down can't cherry-pick.
- In CI the repo is checked out, so `import utils` is known to be local. To
  be fair, each repo's file list comes from a blobless clone (names only).

### 34. Dev/test split (train/test, like in ML)
- **Dev set** (142 PRs, September 2026): labeled, used to find false
  positives, fixed, re-run. Its "after" number (74%) is optimistic.
- **Test set** (143 PRs, August 2026): collected after all fixes; scanned
  once with the frozen tool. Its number (72%) is the honest one.
- *Why:* tuning on data and then reporting on the same data inflates results.
  Reporting both, labeled, is what makes the numbers believable.

### 35. What the dev set taught (36% → 74% precision)
- 20 false positives removed, 0 true positives lost:
  monorepo **workspace packages** (`@workspace/db`: a folder with its own
  `package.json`), **tsconfig path aliases** (`@components/...` when there's a
  `components/` folder and the scope isn't a public npm scope), **`bun:`**
  imports (like `node:`), text inside a regex, **conditional test skips**
  (`if not linux: t.Skip()` is fine: now only a skip as the test's *first
  statement* counts), **tests renamed in place** (now only a *net loss* of
  tests is flagged), and "authorize" in a README.
- Lesson: a fake registry tests logic; only real monorepos show how
  JavaScript projects actually resolve imports.
- Fun find: Strapi's internal `vitest-config` package shares its name with a
  public npm package that npm removed as malware, which looks like a
  dependency-confusion attempt. In the PR it resolves to the workspace, so
  the finding was labeled FP, but it's a real-world example of why the
  check exists.

### 36. Recall by planting problems
- Real PRs almost never contain leaked keys or hallucinated packages, so
  "what did it miss in real PRs" can't measure recall. Instead 32 realistic
  problems are planted into copies of test-set PRs, among real code in files
  of the same language.
- Six out-of-scope cases (a key in `x = "..."`, a custom key format, a
  short password, `cp.exec`, `DELETE` without `WHERE`, a Go module) are
  included and all missed, which documents the limits instead of hiding them.
- **The harness had bugs too, and fixing them was not cheating** (the tool
  didn't change): it wrote `from fastapi-jwt-guardian import` (invalid Python),
  planted into lockfiles and test files where the rule is deliberately off,
  and once planted code *inside a docstring*. Each was a placement that can't
  happen in reality. Final harness: app code only, between real code lines.
- *Caveat:* I wrote both the rules and the plants, so 100% is an upper bound.

### 37. Statistics
- Precision with a **Wilson 95% interval**: with 25 findings, "72%" alone
  hides that the truth could reasonably be anywhere from about 52% to 86%.
  Wilson behaves at small n and near 0/100%, where the textbook
  `p ± 1.96·√(p(1−p)/n)` can go below 0% or above 100%.
- Precision is per finding; recall is per planted problem.

### 38. Data hygiene
- Diffs are **not committed** (`bench/data/` is gitignored): they're other
  people's code, and a real leaked key would be re-published. The PR list,
  scripts, labels and results are committed, so anyone can re-download and
  reproduce.
- GitHub rate-limited diff downloads (HTTP 429) during the first test-set
  collection, and 103 PRs were silently skipped. That changes which PRs get
  picked, so the collector now waits and retries, and the test set was
  re-collected (before the tool was run on it).

### 39. Bugs found by the held-out set are fixed *after* recording its numbers
- The test set exposed 3 more false-positive causes (English in a JS
  comment read as an import, `paho` → `paho-mqtt` missing from the map, a
  `test-harness/` folder not seen as tests). They were fixed in a separate
  commit, after the 72% was recorded, and re-checked: exactly those 3 findings
  disappeared, nothing else changed on either set (82% on the same PRs).
- That 82% is not reported as the headline, because the set stopped being
  held-out the moment I fixed things using it. The next honest number needs
  a fresh set (e.g. October PRs).
- While adding import-name mappings I checked each against PyPI: `nacl`,
  `grpc`, `dns`, `github`, `Bio`... are *also* registered as unrelated packages.
  Without a mapping, the age/typo checks would inspect the wrong package.

### 40. Who labeled
- Labels are by Claude, with written criteria (`bench/LABELING.md`, fixed
  before labeling) and a reason per finding. **Vikhram must spot-check them
  before using the numbers on a resume.**

## Step 7: polish

### 41. The PyPI name "agentshield" is taken
- An unrelated project ("Security and monitoring for AI agents") already owns
  `agentshield` on PyPI. Telling people to `pip install agentshield` would
  install *someone else's code*, the exact confusion this tool warns about.
- So the README installs from source, and publishing waits on picking a free
  distribution name (the command and import can stay `agentshield`, like
  `pip install beautifulsoup4` / `import bs4`). Checked free at the time:
  `agent-shield`, `pr-agentshield`, `agentshield-scan`. **Vikhram's decision.**

### 42. The demo GIF is real output
- `examples/record_demo.py` runs the installed CLI on the demo PR inside a
  pseudo-terminal (so colours and wrapping are exactly what a user sees) and
  writes an asciinema cast; `agg` renders the GIF. No screen recording, no
  editing, and anyone can regenerate it.
- The demo PR is generated at runtime (`examples/demo.py`), so the fake Stripe
  key never sits in the repo as a key-shaped string (#16). A test runs the
  demo, so the README can't silently go stale.

### 43. Word-wrapped text output
- Recording the GIF showed long messages wrapping mid-word ("da/ta is gone")
  and the risk headline scrolling off. The text report now wraps at word
  boundaries (max 100 columns) with a hanging indent under "Fix:".

### 44. Packaging checked without publishing
- Built the sdist and wheel, `twine check` passes, the wheel contains only
  the package + its data files, and a fresh Python 3.11 venv installed it and
  ran a scan from an unrelated directory (data files load via
  `importlib.resources`, not relative paths).
- Added the MIT `LICENSE` text (pyproject only named the licence before).

### 45. The repo scans itself with its own config
- `.agentshield.toml` ignores `bench/`, which holds deliberately planted
  problems and results that quote findings. The report still says "15 file(s)
  skipped by ignore_paths", so the exclusion is visible (#24).

## Open questions (to decide with data)
- `risky.no-tests` is most of the findings (79% precision). Should it be off
  by default, or only fire when the repo already has tests?
- Should plain hardcoded passwords (`password = "hunter2"`, low entropy) be
  flagged? Currently not: test code is full of them.
- Is 30 days the right "new package" cutoff?
- Should download counts factor in? (Needs a stats API.)
- How many false positives on real PRs? This is what the benchmark answers.
