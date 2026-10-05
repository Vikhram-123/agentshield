"""A pretend PyPI/npm so tests run offline and give the same answer every time."""

from datetime import datetime, timedelta, timezone

NOW = datetime(2026, 10, 5, tzinfo=timezone.utc)


def _days_ago(n):
    return (NOW - timedelta(days=n)).isoformat().replace("+00:00", "Z")


PYPI = {  # name -> days since first release
    "reqeusts": 900,     # a real-world style typosquat that has been around a while
    "fastjsonx": 5,      # brand new
    "django-ninja": 1500,
}
NPM = {
    "lodahs": 3,         # new AND a typo of lodash -> high
    "left-pad": 3000,
}


def fake_fetch(url):
    if url.startswith("https://pypi.org/pypi/"):
        name = url.split("/pypi/")[1].split("/json")[0]
        if name not in PYPI:
            return 404, None
        return 200, {"releases": {"1.0": [{"upload_time_iso_8601": _days_ago(PYPI[name])}]}}
    name = url.split("registry.npmjs.org/")[1].replace("%2F", "/")
    if name == "evil-pkg":
        return 200, {"description": "security holding package",
                     "versions": {"0.0.1-security": {}}, "time": {"created": _days_ago(400)}}
    if name not in NPM:
        return 404, None
    return 200, {"versions": {"1.0.0": {}}, "time": {"created": _days_ago(NPM[name])}}


def broken_fetch(url):
    raise OSError("network unreachable")
