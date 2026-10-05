"""Step 1 of the benchmark: choose real pull requests and download their diffs.

    python bench/collect.py --set dev  --window 2026-09-01..2026-09-30
    python bench/collect.py --set test --window 2026-08-01..2026-08-31

Writes bench/prs_<set>.csv; diffs go to bench/data/ (not committed).

Two sets, like a train/test split: "dev" PRs were used to find and fix
false positives; "test" PRs were collected afterwards and only scanned with
the finished tool, so their numbers aren't flattered by tuning.

Selection is mechanical, so nobody (including me) cherry-picks PRs the tool
does well on:
  * AI-assisted PRs: GitHub search for public PRs with an AI tool's marker
    (Claude Code footer, Copilot coding agent, Devin, Cursor co-author),
    created in a fixed window, newest first, at most one PR per repository.
  * Comparison PRs: the newest PRs in the same window from 30 popular
    projects, skipping bots and anything with an AI marker.
  * Every group: diff must download, be a real diff, and have at most
    MAX_DIFF_LINES lines (giant PRs aren't reviewed line by line anyway).

Uses GitHub's public, unauthenticated APIs: search allows 10 requests per
minute, so this sleeps between searches. Diffs come from github.com/<pr>.diff.
"""

from __future__ import annotations

import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "data")          # gitignored: third-party code
MAX_DIFF_LINES = 3000
SEARCH_PAUSE = 7  # seconds; keeps us under 10 searches/minute

AI_GROUPS = {  # group -> (search qualifier, how many PRs)
    "ai-claude-code": ('"Generated with Claude Code"', 40),
    "ai-copilot-agent": ("author:app/copilot-swe-agent", 25),
    "ai-devin": ("author:app/devin-ai-integration", 15),
    "ai-cursor": ('"Co-authored-by: Cursor"', 10),
}
POPULAR_REPOS = [
    "django/django", "pallets/flask", "fastapi/fastapi", "psf/requests", "pandas-dev/pandas",
    "scikit-learn/scikit-learn", "encode/httpx", "apache/airflow", "home-assistant/core",
    "huggingface/transformers", "langchain-ai/langchain", "getsentry/sentry", "python/cpython",
    "expressjs/express", "vercel/next.js", "facebook/react", "vuejs/core", "nodejs/node",
    "sveltejs/svelte", "nestjs/nest", "prisma/prisma", "supabase/supabase", "strapi/strapi",
    "microsoft/vscode", "grafana/grafana", "kubernetes/kubernetes", "rails/rails",
    "mastodon/mastodon", "discourse/discourse", "n8n-io/n8n",
]
PER_POPULAR_REPO = 2
# Signs a PR was written with an AI tool (a PR *about* Copilot doesn't count).
AI_MARKERS = re.compile(r"generated with \[?(claude|cursor|codex)|co-authored-by:\s*(claude|cursor|copilot)|"
                        r"devin-ai-integration|app\.devin\.ai", re.I)
BOT_LOGINS = re.compile(r"\[bot\]$|^(dependabot|renovate|github-actions)", re.I)


def get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "agentshield-bench"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)


def search(query: str, page: int = 1) -> list[dict]:
    q = urllib.parse.quote(query)
    url = f"https://api.github.com/search/issues?q={q}&sort=created&order=desc&per_page=100&page={page}"
    for attempt in range(3):
        try:
            data = get_json(url)
            time.sleep(SEARCH_PAUSE)
            return data.get("items", [])
        except urllib.error.HTTPError as e:
            if e.code == 403 and attempt < 2:  # rate limited: wait for the window to reset
                time.sleep(65)
                continue
            if e.code == 422:  # GitHub couldn't run this query (e.g. repo it won't search)
                print(f"  search rejected (HTTP 422): {query}", file=sys.stderr)
                time.sleep(SEARCH_PAUSE)
                return []
            raise
    return []


def download_diff(repo: str, number: int) -> str | None:
    path = os.path.join(DATA, "diffs", f"{repo.replace('/', '__')}__{number}.diff")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    req = urllib.request.Request(f"https://github.com/{repo}/pull/{number}.diff",
                                 headers={"User-Agent": "agentshield-bench"})
    for attempt in range(6):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                text = resp.read().decode("utf-8", errors="replace")
            break
        except urllib.error.HTTPError as e:
            # 429 = "slow down". Skipping would quietly change which PRs get
            # picked (the first run of the test set lost 103 PRs this way), so wait.
            if e.code == 429 and attempt < 5:
                time.sleep(int(e.headers.get("Retry-After") or 60))
                continue
            return None
        except Exception:
            return None
    else:
        return None
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


def repo_file_list(repo: str) -> list[str] | None:
    """The repo's file names (no contents): a blobless, shallow clone + ls-tree.

    In CI the repo is checked out, so `import utils` is known to be local.
    The benchmark needs the same information to be fair.
    """
    path = os.path.join(DATA, "trees", repo.replace("/", "__") + ".txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            return fh.read().splitlines()
    tmp = os.path.join(DATA, "tmp-clone")
    subprocess.run(["rm", "-rf", tmp], check=True)
    r = subprocess.run(["git", "clone", "--quiet", "--depth", "1", "--filter=blob:none",
                        "--no-checkout", f"https://github.com/{repo}.git", tmp],
                       capture_output=True, text=True, timeout=300,
                       env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
    if r.returncode != 0:
        return None
    files = subprocess.run(["git", "-C", tmp, "ls-tree", "-r", "--name-only", "HEAD"],
                           capture_output=True, text=True).stdout.splitlines()
    subprocess.run(["rm", "-rf", tmp], check=True)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(files))
    return files


def usable(text: str | None) -> tuple[bool, str]:
    if text is None:
        return False, "download failed"
    if not text.startswith("diff --git"):
        return False, "not a diff"
    n = text.count("\n")
    if n > MAX_DIFF_LINES:
        return False, f"too big ({n} lines)"
    return True, ""


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", required=True, choices=["dev", "test"])
    ap.add_argument("--window", required=True, help="created:<window>, e.g. 2026-08-01..2026-08-31")
    args = ap.parse_args()
    window = args.window
    # Never reuse a PR from another set.
    taken: set[str] = set()
    for other in ("dev", "test"):
        path = os.path.join(HERE, f"prs_{other}.csv")
        if other != args.set and os.path.exists(path):
            with open(path, newline="") as fh:
                taken |= {row["id"] for row in csv.DictReader(fh)}

    rows: list[dict] = []
    skipped: dict[str, int] = {}
    seen_repos: set[str] = set()

    def consider(item: dict, group: str) -> bool:
        repo = item["repository_url"].split("/repos/")[1]
        if f"{repo}#{item['number']}" in taken:
            return False
        ok, why = usable(download_diff(repo, item["number"]))
        if not ok:
            skipped[why.split(" (")[0]] = skipped.get(why.split(" (")[0], 0) + 1
            return False
        rows.append({"id": f"{repo}#{item['number']}", "group": group, "repo": repo,
                     "number": item["number"], "url": item["html_url"],
                     "author": item["user"]["login"], "created": item["created_at"][:10]})
        seen_repos.add(repo)
        return True

    for group, (qualifier, want) in AI_GROUPS.items():
        got = 0
        for page in (1, 2, 3):
            items = search(f"is:pr is:public {qualifier} created:{window}", page)
            for item in items:
                repo = item["repository_url"].split("/repos/")[1]
                if repo in seen_repos:  # one PR per repo, so no single project dominates
                    continue
                if consider(item, group):
                    got += 1
                if got == want:
                    break
            if got == want or not items:
                break
        print(f"{group}: {got} PRs", file=sys.stderr)

    for repo in POPULAR_REPOS:
        got = 0
        for item in search(f"is:pr repo:{repo} created:{window}"):
            login = item["user"]["login"]
            if BOT_LOGINS.search(login) or login == "Copilot" or AI_MARKERS.search(item.get("body") or ""):
                continue
            if consider(item, "no-ai-marker"):
                got += 1
            if got == PER_POPULAR_REPO:
                break
        print(f"{repo}: {got} PRs", file=sys.stderr)

    for r in rows:
        files = repo_file_list(r["repo"])
        r["repo_files"] = "yes" if files is not None else "no"

    with open(os.path.join(HERE, f"prs_{args.set}.csv"), "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"{len(rows)} PRs written to bench/prs_{args.set}.csv; skipped: {skipped}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
