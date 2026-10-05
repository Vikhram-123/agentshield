import io
import json
import os
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
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".diff", delete=False) as fh:
            fh.write("<!DOCTYPE html><html>Not Found</html>")
        try:
            buf = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(io.StringIO()):
                code = cli.main(["scan", "--diff", fh.name, "--offline"])
            self.assertEqual((code, buf.getvalue()), (2, ""))
        finally:
            os.unlink(fh.name)


if __name__ == "__main__":
    unittest.main()
