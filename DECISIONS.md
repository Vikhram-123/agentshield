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

## Open questions (to decide with data)
- Should plain hardcoded passwords (`password = "hunter2"`, low entropy) be
  flagged? Currently not: test code is full of them.
- Is 30 days the right "new package" cutoff?
- Should download counts factor in? (Needs a stats API.)
- How many false positives on real PRs? This is what the benchmark answers.
