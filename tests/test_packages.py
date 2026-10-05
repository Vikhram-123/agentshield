import os
import unittest

from agentshield.checks.packages import check_packages, extract_dependencies
from agentshield.diff import parse_diff
from agentshield.findings import Severity
from agentshield.registry import Registry

from .fake_registry import NOW, broken_fetch, fake_fetch

HERE = os.path.dirname(__file__)
NO_REPO = os.path.join(HERE, "does-not-exist")  # don't scan the real disk in tests


def load(name):
    with open(os.path.join(HERE, "fixtures", name), encoding="utf-8") as fh:
        return parse_diff(fh.read())


def by_name(findings):
    """Map package name (pulled from the message) -> finding, for easy asserts."""
    out = {}
    for f in findings:
        name = f.message.split('"')[1]
        out[name] = f
    return out


class ExtractTest(unittest.TestCase):
    def test_filters_stdlib_local_relative_and_builtins(self):
        files = load("ai_pr.diff")
        names = {d.name for d in extract_dependencies(files, {"utils", "app"})}
        for skipped in ["os", "json", "utils", "models", "google", "fs", "thing", "build", "version"]:
            self.assertNotIn(skipped, names)
        for kept in ["requests", "flask-auth-helper", "reqeusts", "fastjsonx",
                     "pyyaml", "langchain_memory_tools", "express",
                     "react-fast-hooks-x", "lodahs", "@ai-utils/super-fetch"]:
            self.assertIn(kept, names)

    def test_requirements_edge_cases(self):
        diff = ("diff --git a/requirements.txt b/requirements.txt\n--- a/requirements.txt\n"
                "+++ b/requirements.txt\n@@ -0,0 +1,6 @@\n+-r base.txt\n+# comment\n"
                "+git+https://github.com/x/y.git\n+uvicorn[standard]>=0.29\n"
                "+Django ; python_version >= '3.10'\n+\n")
        names = {d.name for d in extract_dependencies(parse_diff(diff), set())}
        self.assertEqual(names, {"uvicorn", "Django"})


class CheckPackagesTest(unittest.TestCase):
    def setUp(self):
        findings, self.notes = check_packages(load("ai_pr.diff"), Registry(fake_fetch),
                                              repo_root=NO_REPO, now=NOW)
        self.f = by_name(findings)

    def test_hallucinated_manifest_entry_is_high(self):
        f = self.f["flask-auth-helper"]
        self.assertEqual((f.rule, f.severity, f.file, f.line),
                         ("package.not-found", Severity.HIGH, "requirements.txt", 4))
        self.assertEqual(self.f["react-fast-hooks-x"].severity, Severity.HIGH)

    def test_hallucinated_import_is_medium(self):
        self.assertEqual(self.f["langchain_memory_tools"].severity, Severity.MEDIUM)
        self.assertEqual(self.f["@ai-utils/super-fetch"].severity, Severity.MEDIUM)

    def test_typosquat_old_is_medium_new_is_high(self):
        self.assertEqual(self.f["reqeusts"].rule, "package.typosquat")
        self.assertEqual(self.f["reqeusts"].severity, Severity.MEDIUM)
        self.assertEqual(self.f["lodahs"].severity, Severity.HIGH)
        self.assertIn('"lodash"', self.f["lodahs"].message)

    def test_brand_new_package(self):
        self.assertEqual(self.f["fastjsonx"].rule, "package.new")

    def test_popular_and_local_packages_not_flagged(self):
        for ok in ["requests", "pyyaml", "express", "utils"]:
            self.assertNotIn(ok, self.f)
        self.assertEqual(len(self.f), 7)

    def test_malware_takedown(self):
        diff = ('diff --git a/package.json b/package.json\n--- a/package.json\n+++ b/package.json\n'
                '@@ -1 +1,2 @@\n {\n+  "evil-pkg": "^1.0.0",\n')
        findings, _ = check_packages(parse_diff(diff), Registry(fake_fetch), repo_root=NO_REPO, now=NOW)
        self.assertEqual(findings[0].rule, "package.malware-removed")

    def test_network_failure_becomes_note_not_crash(self):
        findings, notes = check_packages(load("ai_pr.diff"), Registry(broken_fetch),
                                         repo_root=NO_REPO, now=NOW)
        rules = {f.rule for f in findings}
        self.assertNotIn("package.not-found", rules)  # never claim "missing" when we couldn't check
        self.assertTrue(any("network unreachable" in n for n in notes))

    def test_offline_mode_still_catches_typos(self):
        findings, notes = check_packages(load("ai_pr.diff"), None, repo_root=NO_REPO, now=NOW)
        self.assertEqual({f.rule for f in findings}, {"package.typosquat"})
        self.assertTrue(any("Offline" in n for n in notes))


if __name__ == "__main__":
    unittest.main()
