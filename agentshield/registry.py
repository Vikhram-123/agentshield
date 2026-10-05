"""Ask PyPI and npm about a package: does it exist, and how old is it?

Both registries have free public JSON APIs:
    https://pypi.org/pypi/<name>/json
    https://registry.npmjs.org/<name>

A 404 means the package does not exist. That is the core signal for a
hallucinated package.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from .similarity import normalize

USER_AGENT = "agentshield/0.1 (+https://github.com/)"
TIMEOUT_SECONDS = 6


@dataclass
class PackageInfo:
    exists: bool | None             # None = couldn't check (offline, timeout)
    created: datetime | None = None  # first ever release
    release_count: int = 0
    malware_removed: bool = False    # npm swaps malware for a "security holding" stub
    error: str | None = None

    def age_days(self, now: datetime | None = None) -> int | None:
        if self.created is None:
            return None
        now = now or datetime.now(timezone.utc)
        return (now - self.created).days


# A fetcher takes a URL and returns (HTTP status, parsed JSON or None).
# Tests swap in a fake one so they never touch the internet.
Fetcher = Callable[[str], "tuple[int, dict | None]"]


def http_fetch(url: str) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
            return resp.status, json.load(resp)
    except urllib.error.HTTPError as e:
        return e.code, None


class Registry:
    def __init__(self, fetch: Fetcher = http_fetch):
        self.fetch = fetch
        self._cache: dict[tuple[str, str], PackageInfo] = {}

    def lookup(self, ecosystem: str, name: str) -> PackageInfo:
        key = (ecosystem, name.lower())
        if key not in self._cache:
            try:
                if ecosystem == "pypi":
                    self._cache[key] = self._pypi(name)
                else:
                    self._cache[key] = self._npm(name)
            except Exception as e:  # network down, DNS, timeout, bad JSON
                self._cache[key] = PackageInfo(exists=None, error=str(e) or type(e).__name__)
        return self._cache[key]

    def _pypi(self, name: str) -> PackageInfo:
        status, data = self.fetch(f"https://pypi.org/pypi/{normalize(name)}/json")
        if status == 404:
            return PackageInfo(exists=False)
        if status != 200 or data is None:
            return PackageInfo(exists=None, error=f"PyPI returned HTTP {status}")
        uploads = [
            f.get("upload_time_iso_8601") or f.get("upload_time")
            for files in (data.get("releases") or {}).values()
            for f in files
        ]
        uploads = [u for u in uploads if u]
        if not uploads:  # older API shape: fall back to the latest release's files
            uploads = [f.get("upload_time_iso_8601") or f.get("upload_time")
                       for f in data.get("urls") or []]
            uploads = [u for u in uploads if u]
        created = min((_parse_time(u) for u in uploads), default=None)
        return PackageInfo(exists=True, created=created,
                           release_count=len(data.get("releases") or {}))

    def _npm(self, name: str) -> PackageInfo:
        # Scoped names like @types/node must keep "@" but encode the "/".
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@")
        status, data = self.fetch(url)
        if status == 404:
            return PackageInfo(exists=False)
        if status != 200 or data is None:
            return PackageInfo(exists=None, error=f"npm returned HTTP {status}")
        times = data.get("time") or {}
        if "unpublished" in times:
            return PackageInfo(exists=False)
        versions = data.get("versions") or {}
        malware = (list(versions) == ["0.0.1-security"]
                   or "security holding package" in (data.get("description") or "").lower())
        created = _parse_time(times["created"]) if times.get("created") else None
        return PackageInfo(exists=True, created=created,
                           release_count=len(versions), malware_removed=malware)


def _parse_time(value: str) -> datetime:
    value = value.replace("Z", "+00:00")
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
