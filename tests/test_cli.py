import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agentshield import cli

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "ai_pr.diff")


class CliTest(unittest.TestCase):
    def run_cli(self, *args):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli.main(["scan", "--diff", FIXTURE, "--offline", "--repo", "/nonexistent", *args])
        return code, buf.getvalue()

    def test_json_output_and_exit_code(self):
        code, out = self.run_cli("--format", "json")
        data = json.loads(out)
        self.assertEqual(data["files_scanned"], 5)
        self.assertGreater(data["risk_score"], 0)
        self.assertEqual(code, 0)  # offline: only medium typos, below the default "high" bar

    def test_fail_on_medium(self):
        code, _ = self.run_cli("--fail-on", "medium")
        self.assertEqual(code, 1)

    def test_text_and_markdown_render(self):
        _, text = self.run_cli("--no-color")
        self.assertIn("AgentShield report", text)
        self.assertIn("Fix:", text)
        _, md = self.run_cli("--format", "markdown")
        self.assertIn("| Issue |", md)

    def test_non_diff_input_is_an_error_not_clean(self):
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as fh:
            fh.write("<!DOCTYPE html><html>Not Found</html>")
        try:
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = cli.main(["scan", "--diff", fh.name, "--offline"])
            self.assertEqual((code, buf.getvalue()), (2, ""))
        finally:
            os.unlink(fh.name)

    def test_readme_demo_still_works(self):
        """examples/demo.py is in the README and the GIF: keep it honest."""
        import importlib.util
        path = os.path.join(os.path.dirname(__file__), "..", "examples", "demo.py")
        spec = importlib.util.spec_from_file_location("demo", path)
        demo = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(demo)
        with tempfile.TemporaryDirectory() as tmp:
            diff = os.path.join(tmp, "pr.diff")
            with open(diff, "w") as fh:
                fh.write(demo.demo_diff())
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = cli.main(["scan", "--diff", diff, "--offline", "--repo", tmp, "--format", "json"])
        rules = {f["rule"] for f in json.loads(buf.getvalue())["findings"]}
        self.assertEqual(code, 1)
        self.assertTrue({"secret.stripe-key", "risky.destructive-migration", "package.typosquat",
                         "risky.insecure-setting", "risky.dangerous-call", "risky.test-skipped"} <= rules)


if __name__ == "__main__":
    unittest.main()
