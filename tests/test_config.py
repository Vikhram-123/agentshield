import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agentshield import cli
from agentshield.config import Config, ConfigError, apply_ignores, load_config, parse_config
from agentshield.findings import Finding, Severity

from .helpers import fake_secret, files_from, make_diff


def finding(rule, file="a.py", line=1):
    return Finding(rule, Severity.MEDIUM, file, line, "msg", "fix")


class ParseTest(unittest.TestCase):
    def test_full_config(self):
        cfg = parse_config({"fail_on": "medium", "fail_score": 60, "ignore_paths": ["vendor/"],
                            "ignore_rules": ["risky.no-tests"], "allow_packages": ["@acme/*"],
                            "new_package_days": 14})
        self.assertEqual((cfg.fail_on, cfg.fail_score, cfg.new_package_days), ("medium", 60, 14))

    def test_typos_and_bad_values_are_errors(self):
        for bad in ({"ignore_path": ["x"]}, {"fail_on": "critical"}, {"fail_score": 101},
                    {"fail_score": True}, {"ignore_rules": "risky.no-tests"},
                    {"allow_packages": [1, 2]}):
            with self.subTest(bad=bad), self.assertRaises(ConfigError):
                parse_config(bad)

    def test_missing_file_means_defaults(self):
        self.assertEqual(load_config("/nonexistent").ignore_rules, [])

    def test_invalid_toml_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, ".agentshield.toml"), "w") as fh:
                fh.write("fail_on = [unclosed")
            with self.assertRaises(ConfigError):
                load_config(d)


class MatchingTest(unittest.TestCase):
    def test_paths(self):
        cfg = Config(ignore_paths=["vendor/", "docs/**", "*.min.js", "legacy/*.py"])
        for p in ["vendor/x.py", "web/vendor/y.js", "docs/a/b.md", "static/app.min.js", "legacy/old.py"]:
            self.assertTrue(cfg.path_ignored(p), p)
        for p in ["src/vendors.py", "app.js", "legacy.py", "mydocs/a.md"]:
            self.assertFalse(cfg.path_ignored(p), p)

    def test_rule_prefixes(self):
        cfg = Config(ignore_rules=["secret.*", "risky.no-tests"])
        self.assertTrue(cfg.rule_ignored("secret.jwt"))
        self.assertTrue(cfg.rule_ignored("risky.no-tests"))
        self.assertFalse(cfg.rule_ignored("risky.no-tests-extra"))
        self.assertFalse(cfg.rule_ignored("risky.dangerous-call"))
        self.assertFalse(cfg.rule_ignored("secretive.x"))  # prefix means a whole segment

    def test_packages_normalized_and_wildcards(self):
        cfg = Config(allow_packages=["Acme_SDK", "@acme/*"])
        self.assertTrue(cfg.package_allowed("acme-sdk"))
        self.assertTrue(cfg.package_allowed("@acme/ui"))
        self.assertFalse(cfg.package_allowed("acme"))


class InlineIgnoreTest(unittest.TestCase):
    def setUp(self):
        self.files = files_from(make_diff("a.py", [
            "x = eval(s)  # agentshield: ignore",
            "y = eval(s)  # agentshield: ignore[risky.dangerous-call]",
            "z = eval(s)  # agentshield: ignore[secret.jwt]",
            "w = eval(s)",
        ]))

    def test_bare_specific_and_wrong_rule(self):
        findings = [finding("risky.dangerous-call", line=n) for n in (1, 2, 3, 4)]
        kept, notes = apply_ignores(findings, self.files, Config())
        self.assertEqual([f.line for f in kept], [3, 4])
        self.assertIn("2 finding(s) hidden by inline", notes[0])

    def test_findings_without_a_line_are_not_inline_ignorable(self):
        kept, _ = apply_ignores([finding("risky.no-tests", line=None)], self.files, Config())
        self.assertEqual(len(kept), 1)


class CliConfigTest(unittest.TestCase):
    """End to end: a real config file in a temp repo changes the result."""

    def scan(self, config_text, diff, *args):
        with tempfile.TemporaryDirectory() as repo:
            with open(os.path.join(repo, ".agentshield.toml"), "w") as fh:
                fh.write(config_text)
            diff_path = os.path.join(repo, "pr.diff")
            with open(diff_path, "w") as fh:
                fh.write(diff)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = cli.main(["scan", "--diff", diff_path, "--offline", "--repo", repo,
                                 "--format", "json", *args])
            return code, out.getvalue(), err.getvalue()

    KEY_DIFF = make_diff("app/config.py", ['TOKEN = "ghp_' + fake_secret(36, 30) + '"'])

    def test_no_config_fails_on_leaked_key(self):
        code, out, _ = self.scan("", self.KEY_DIFF)
        self.assertEqual(code, 1)
        self.assertIn("secret.github-token", out)

    def test_ignore_paths_and_rules(self):
        code, out, _ = self.scan('ignore_paths = ["app/"]', self.KEY_DIFF)
        self.assertEqual(code, 0)
        self.assertIn("skipped by ignore_paths", out)
        code, out, _ = self.scan('ignore_rules = ["secret"]', self.KEY_DIFF)
        self.assertEqual(code, 0)
        self.assertIn("hidden by ignore_rules", out)

    def test_fail_on_from_config_and_cli_override(self):
        diff = make_diff("app/run.py", ["x = eval(s)"])  # one MEDIUM finding
        self.assertEqual(self.scan('fail_on = "medium"', diff)[0], 1)
        self.assertEqual(self.scan('fail_on = "medium"', diff, "--fail-on", "high")[0], 0)

    def test_fail_score(self):
        diff = make_diff("app/run.py", ["x = eval(s)", "y = exec(s)"])  # 15 + 15 = 30
        self.assertEqual(self.scan("fail_score = 30", diff)[0], 1)
        self.assertEqual(self.scan("fail_score = 31", diff)[0], 0)
        self.assertEqual(self.scan("fail_score = 30", diff, "--fail-on", "never")[0], 0)

    def test_allow_packages(self):
        diff = make_diff("requirements.txt", ["reqeust"])  # typo of "requests" (offline still checks)
        self.assertIn("package.typosquat", self.scan("", diff)[1])
        self.assertNotIn("package.typosquat", self.scan('allow_packages = ["reqeust"]', diff)[1])

    def test_bad_config_exits_2(self):
        code, out, err = self.scan('ignore_path = ["x"]', self.KEY_DIFF)
        self.assertEqual((code, out), (2, ""))
        self.assertIn("unknown setting", err)


if __name__ == "__main__":
    unittest.main()
