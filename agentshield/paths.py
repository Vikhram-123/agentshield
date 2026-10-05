"""What kind of file is this? Shared by the checks.

Path conventions are the only cheap signal we have: we see a diff, not a
build system, so "tests/test_x.py" is a test because that's where tests live.
"""

from __future__ import annotations

import re

# Real tests: these are what a "did the PR touch tests?" question cares about.
# tests/, test/, test-harness/, test_utils/, __tests__/, spec/, e2e/ ...
TEST_DIR_RE = re.compile(r"(^|/)(tests?([-_][\w-]+)?|__tests__|specs?|e2e|testing)/", re.I)
TEST_FILE_RE = re.compile(
    r"(^|/)(test_[^/]*\.\w+|[^/]*_test\.\w+|[^/]*Tests?\.(java|kt|cs|swift)|"
    r"[^/]*\.(test|spec)\.\w+|conftest\.py)$")
# Fake data and samples: secrets found here are usually not real.
FIXTURE_RE = re.compile(
    r"(^|/)(fixtures?|testdata|mocks?|examples?|samples?)/|\.(example|sample|template)$", re.I)

SOURCE_EXTS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte",
               ".go", ".rb", ".java", ".kt", ".rs", ".php", ".cs", ".swift", ".scala",
               ".c", ".cc", ".cpp", ".h", ".hpp")


def is_test_path(path: str) -> bool:
    return bool(TEST_DIR_RE.search(path) or TEST_FILE_RE.search(path))


def is_fixture_path(path: str) -> bool:
    return bool(FIXTURE_RE.search(path))


def is_source_path(path: str) -> bool:
    """Application code (not tests, docs, config or fixtures)."""
    return (path.endswith(SOURCE_EXTS) and not is_test_path(path)
            and not is_fixture_path(path))
