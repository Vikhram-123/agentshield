# How findings were labeled

Written **before** looking at the results, so the rules can't be bent to make
the numbers look better.

Each finding gets one label:

- **TP** (true positive): the finding's claim is correct for that line, and a
  careful reviewer of this PR would want to be told.
- **FP** (false positive): the claim is wrong (not a secret, the package
  exists, not a real migration...) **or** it is technically true but
  irrelevant in context (e.g. `eval` inside a build script's own constant).

Severity is not judged separately: a correct finding at the "wrong" severity
is still TP, but is mentioned in the reason.

## Per rule

| Rule | TP when... | FP when... |
|---|---|---|
| `package.not-found` | the name really isn't on PyPI/npm **as a dependency the PR adds** | it's a local module, a workspace package, a renamed import we don't map, a private registry package |
| `package.typosquat` | the name looks like a mistake or attack | it's a real, intended, well-known package that just happens to be 1-2 edits from a popular one |
| `package.new` | the package is in fact young (always true if the registry says so) and not the PR author's own package | the PR is publishing/using its own new package from the same org |
| `secret.*` | it looks like a real credential (format + randomness + context) | placeholder, test fixture, documented example, public key, hash |
| `risky.auth-change` | the file really is authentication / authorization code | the path word is a coincidence (e.g. "login" page styling only) |
| `risky.auth-guard-removed` | an access check was really removed, not moved | the check moved or was replaced in the same diff |
| `risky.destructive-migration` | a real schema/data drop that would run | a down-migration, a test, or SQL that isn't executed |
| `risky.test-deleted` | a test really went away | it was renamed/moved, or the tested code was deleted too (still flagged TP: the rule's purpose is to make a human confirm) |
| `risky.test-skipped` | a test is really disabled / `.only`'d in committed code | a string, a conditional platform skip |
| `risky.no-tests` | ≥10 lines of behaviour changed and no tests touched | the "source" is generated code, config written in code, or pure types/constants |
| `risky.insecure-setting` | the setting applies to running code (app, server, scripts) | local-dev-only file clearly marked, or an example/doc |
| `risky.dangerous-call` | the call is really executed in non-test code | it's a different function with the same name, or a string |

## Who labeled

Labels were assigned by Claude (the AI assistant that built AgentShield),
reading each finding in its diff context with `bench/show.py`. **They need a
human spot-check before the numbers are used anywhere.** The `reason` column
explains each call so a reviewer can disagree quickly.
