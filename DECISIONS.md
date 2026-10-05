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

## Open questions (to decide with data)
- Is 30 days the right "new package" cutoff?
- Should download counts factor in? (Needs a stats API.)
- How many false positives on real PRs? This is what the benchmark answers.
