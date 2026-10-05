"""Post the markdown report as a pull request comment (used by action.yml).

    python -m agentshield.github_comment report.md

On every push to a PR the report changes. Posting a new comment each time
would bury the conversation, so we put an invisible marker in our comment
and edit that one comment if it already exists.

Reads the standard variables GitHub Actions provides: GITHUB_TOKEN,
GITHUB_REPOSITORY ("owner/repo"), GITHUB_EVENT_PATH (JSON describing the
event, which holds the PR number) and GITHUB_API_URL.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Callable

MARKER = "<!-- agentshield-report -->"
MAX_PAGES = 10  # 1,000 comments is plenty to find ours

# (method, url, token, body or None) -> (HTTP status, parsed JSON or None)
Requester = Callable[[str, str, str, "dict | None"], "tuple[int, object]"]


def http_request(method: str, url: str, token: str, body: dict | None) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "agentshield",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None


def upsert_comment(api: str, repo: str, pr: int, token: str, report: str,
                   request: Requester = http_request) -> str:
    """Create or update our comment. Returns "created", "updated" or "forbidden"."""
    body = {"body": f"{MARKER}\n{report}"}
    base = f"{api}/repos/{repo}/issues/{pr}/comments"  # PR comments live under "issues"

    existing = None
    for page in range(1, MAX_PAGES + 1):
        status, comments = request("GET", f"{base}?per_page=100&page={page}", token, None)
        if status in (401, 403, 404):
            return "forbidden"
        if status != 200:
            raise RuntimeError(f"listing comments failed: HTTP {status}")
        existing = next((c for c in comments if MARKER in (c.get("body") or "")), None)
        if existing or len(comments) < 100:
            break

    if existing:
        status, _ = request("PATCH", f"{api}/repos/{repo}/issues/comments/{existing['id']}",
                            token, body)
        result = "updated"
    else:
        status, _ = request("POST", base, token, body)
        result = "created"
    if status in (401, 403, 404):
        return "forbidden"
    if status not in (200, 201):
        raise RuntimeError(f"posting comment failed: HTTP {status}")
    return result


def pr_number(event_path: str) -> int | None:
    with open(event_path, encoding="utf-8") as fh:
        event = json.load(fh)
    pr = event.get("pull_request") or {}
    return pr.get("number")


def main(argv: list[str] | None = None, request: Requester = http_request) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m agentshield.github_comment REPORT.md", file=sys.stderr)
        return 2
    with open(argv[0], encoding="utf-8") as fh:
        report = fh.read()
    if not report.strip():
        print("::warning::AgentShield produced no report; not commenting.")
        return 0

    env = os.environ
    token, repo, event_path = env.get("GITHUB_TOKEN"), env.get("GITHUB_REPOSITORY"), env.get("GITHUB_EVENT_PATH")
    if not (token and repo and event_path):
        print("::warning::Not running in GitHub Actions with a token; not commenting.")
        return 0
    pr = pr_number(event_path)
    if pr is None:
        print("::notice::Not a pull request event; the report is in the job summary only.")
        return 0

    result = upsert_comment(env.get("GITHUB_API_URL", "https://api.github.com"),
                            repo, pr, token, report, request)
    if result == "forbidden":
        # Normal for PRs from forks: GitHub gives them a read-only token.
        print("::warning::No permission to comment (PR from a fork, or the workflow lacks "
              "'pull-requests: write'). The report is in the job summary.")
    else:
        print(f"AgentShield comment {result} on PR #{pr}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
