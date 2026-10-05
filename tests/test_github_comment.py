import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from agentshield import github_comment
from agentshield.github_comment import MARKER, upsert_comment

API = "https://api.github.test"


class FakeGitHub:
    """Remembers comments on one PR and records every request."""

    def __init__(self, comments=(), deny=False):
        self.comments = [dict(c) for c in comments]
        self.deny = deny
        self.calls = []

    def __call__(self, method, url, token, body):
        self.calls.append((method, url))
        if self.deny and method != "GET":
            return 403, None
        if method == "GET":
            page = int(url.split("&page=")[1])
            return 200, self.comments[(page - 1) * 100: page * 100]
        if method == "POST":
            self.comments.append({"id": 999, "body": body["body"]})
            return 201, {}
        if method == "PATCH":
            cid = int(url.rsplit("/", 1)[1])
            next(c for c in self.comments if c["id"] == cid)["body"] = body["body"]
            return 200, {}
        raise AssertionError(method)


class UpsertTest(unittest.TestCase):
    def test_creates_when_missing(self):
        gh = FakeGitHub([{"id": 1, "body": "LGTM"}])
        self.assertEqual(upsert_comment(API, "o/r", 7, "t", "report", gh), "created")
        self.assertTrue(gh.comments[-1]["body"].startswith(MARKER))
        self.assertEqual(gh.calls[-1], ("POST", f"{API}/repos/o/r/issues/7/comments"))

    def test_updates_existing_instead_of_spamming(self):
        gh = FakeGitHub([{"id": 1, "body": "LGTM"}, {"id": 2, "body": MARKER + "\nold"}])
        self.assertEqual(upsert_comment(API, "o/r", 7, "t", "new", gh), "updated")
        self.assertEqual(len(gh.comments), 2)
        self.assertIn("new", gh.comments[1]["body"])

    def test_finds_our_comment_on_a_later_page(self):
        many = [{"id": i, "body": "chat"} for i in range(150)] + [{"id": 500, "body": MARKER}]
        gh = FakeGitHub(many)
        self.assertEqual(upsert_comment(API, "o/r", 7, "t", "x", gh), "updated")

    def test_fork_pr_without_permission(self):
        gh = FakeGitHub(deny=True)
        self.assertEqual(upsert_comment(API, "o/r", 7, "t", "x", gh), "forbidden")


class MainTest(unittest.TestCase):
    def run_main(self, event, report="## report", env_extra=None):
        with tempfile.TemporaryDirectory() as d:
            ev, rep = os.path.join(d, "event.json"), os.path.join(d, "r.md")
            with open(ev, "w") as fh:
                json.dump(event, fh)
            with open(rep, "w") as fh:
                fh.write(report)
            env = {"GITHUB_TOKEN": "t", "GITHUB_REPOSITORY": "o/r", "GITHUB_EVENT_PATH": ev,
                   "GITHUB_API_URL": API, **(env_extra or {})}
            gh = FakeGitHub()
            out = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=True), redirect_stdout(out):
                code = github_comment.main([rep], request=gh)
            return code, out.getvalue(), gh

    def test_posts_on_pull_request(self):
        code, out, gh = self.run_main({"pull_request": {"number": 12}})
        self.assertEqual(code, 0)
        self.assertIn("created on PR #12", out)

    def test_push_event_does_not_comment(self):
        code, out, gh = self.run_main({"ref": "refs/heads/main"})
        self.assertEqual((code, gh.calls), (0, []))

    def test_empty_report_does_not_comment(self):
        code, out, gh = self.run_main({"pull_request": {"number": 12}}, report="")
        self.assertEqual((code, gh.calls), (0, []))

    def test_forbidden_is_a_warning_not_a_failure(self):
        with mock.patch.object(github_comment, "upsert_comment", return_value="forbidden"):
            code, out, _ = self.run_main({"pull_request": {"number": 12}})
        self.assertEqual(code, 0)
        self.assertIn("::warning::", out)


if __name__ == "__main__":
    unittest.main()
