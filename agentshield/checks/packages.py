"""Hallucinated package check.

Steps:
  1. EXTRACT every dependency the diff adds: lines in requirements.txt,
     pyproject.toml and package.json, plus import statements in code.
  2. FILTER out things that are not third-party packages: the standard
     library, Node built-ins, relative imports and the repo's own modules.
  3. VERIFY each remaining name against PyPI / npm.
  4. JUDGE: missing -> hallucinated; very new -> possible slopsquat;
     one typo away from a popular package -> possible typosquat.

Manifest entries (requirements.txt, package.json) are what actually get
installed, so problems there are HIGH. An unknown import is MEDIUM: the
import name can legitimately differ from the package name.
"""

from __future__ import annotations

import json
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime
from typing import Callable
from importlib import resources

from ..diff import FileDiff
from ..findings import Finding, Severity
from ..registry import PackageInfo, Registry
from ..similarity import closest, normalize

NEW_PACKAGE_DAYS = 30

NODE_BUILTINS = {
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console",
    "constants", "crypto", "dgram", "diagnostics_channel", "dns", "domain",
    "events", "fs", "http", "http2", "https", "inspector", "module", "net",
    "os", "path", "perf_hooks", "process", "punycode", "querystring",
    "readline", "repl", "stream", "string_decoder", "sys", "timers", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads",
    "zlib", "test",
}
# Import roots that are shared namespaces, not installable packages themselves.
PY_NAMESPACE_ROOTS = {"google", "azure", "jaraco", "zope", "backports"}
JS_EXTS = (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte")
# Public npm scopes. A "@scope/x" import whose scope matches a folder in the
# repo is usually a path alias (tsconfig "paths"), unless it's one of these.
KNOWN_NPM_SCOPES = {
    "types", "babel", "angular", "vue", "nestjs", "aws-sdk", "google-cloud", "azure", "octokit",
    "sentry", "storybook", "testing-library", "typescript-eslint", "vitejs", "sveltejs",
    "remix-run", "nuxt", "radix-ui", "headlessui", "heroicons", "fortawesome", "fontsource",
    "vercel", "next", "firebase", "stripe", "clerk", "trpc", "hookform", "floating-ui", "dnd-kit",
    "tiptap", "mantine", "chakra-ui", "react-native", "expo", "react-navigation", "apollo",
    "prisma", "supabase", "tanstack", "mui", "emotion", "reduxjs", "playwright", "anthropic-ai",
    "openai", "langchain", "ai-sdk", "eslint", "jest", "rollup", "esbuild", "swc", "nx",
    "opentelemetry", "grpc", "fastify", "hono", "solidjs", "shopify", "tailwindcss", "vueuse",
}
# Valid npm package names (after removing any sub-path). Anything else, like
# text from inside a regex, can't be a package.
NPM_NAME_RE = re.compile(r"^(@[a-z0-9~][\w.~-]*/)?[a-z0-9~][\w.~-]*$", re.I)
SKIP_DIRS = {".git", ".venv", "venv", "env", "node_modules", "__pycache__",
             "build", "dist", ".tox", ".mypy_cache", ".idea", "site-packages"}


@dataclass(frozen=True)
class Dependency:
    ecosystem: str   # "pypi" or "npm"
    name: str        # the name we look up in the registry
    file: str
    line: int
    source: str      # "manifest" or "import"
    as_written: str  # what the code actually said, e.g. the import name


# ---------------------------------------------------------------- loading data

def _load_list(filename: str) -> list[str]:
    text = resources.files("agentshield").joinpath("data", filename).read_text()
    return [ln.strip() for ln in text.splitlines()
            if ln.strip() and not ln.startswith("#")]


POPULAR = {
    "pypi": {normalize(n) for n in _load_list("popular_pypi.txt")},
    "npm": {n.lower() for n in _load_list("popular_npm.txt")},
}
IMPORT_TO_PYPI = dict(ln.split() for ln in _load_list("import_names.txt"))
PY_STDLIB = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}


# ------------------------------------------------------------------ extraction

REQ_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;@ ].*)?$")
PYPROJECT_DEP_RE = re.compile(r"""^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*([<>=!~;].*)?["'],?\s*$""")
PY_IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*)")
PY_FROM_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s")
PKG_JSON_DEP_RE = re.compile(r"""^\s*"(@?[a-z0-9][\w.\-]*(?:/[\w.\-]+)?)"\s*:\s*"([^"]*)",?\s*$""", re.I)
NPM_VERSION_RE = re.compile(r"^(\^|~|>=?|<=?|=|\d|\*|x$|latest|next|npm:|workspace:|file:|link:|git|github:|https?:)")
JS_IMPORT_RES = [
    re.compile(r"""\brequire\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)"""),
    re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
    re.compile(r"""^\s*import\s+['"]([^'"]+)['"]"""),
]


def extract_dependencies(files: list[FileDiff], local_modules: set[str],
                         workspace: set[str] = frozenset()) -> list[Dependency]:
    """local_modules: folder and module names in the repo.
    workspace: npm packages the repo itself contains (monorepo workspaces).
    """
    deps: list[Dependency] = []
    for f in files:
        base = os.path.basename(f.path).lower()
        for added in f.added:
            line = added.text
            if base.startswith("requirements") and base.endswith(".txt"):
                deps += _from_requirements(f.path, added.number, line)
            elif base == "pyproject.toml":
                m = PYPROJECT_DEP_RE.match(line)
                if m:
                    deps.append(Dependency("pypi", m.group(1), f.path, added.number, "manifest", m.group(1)))
            elif base == "package.json":
                m = PKG_JSON_DEP_RE.match(line)
                if (m and NPM_VERSION_RE.match(m.group(2).strip())
                        and m.group(1).lower() not in {"node", "npm", "yarn", "pnpm", "version"}
                        and not _in_workspace(m.group(1), workspace)):
                    deps.append(Dependency("npm", m.group(1), f.path, added.number, "manifest", m.group(1)))
            elif f.path.endswith(".py"):
                deps += _from_python(f.path, added.number, line, local_modules)
            elif f.path.endswith(JS_EXTS):
                deps += _from_js(f.path, added.number, line, local_modules, workspace)
    return _dedupe(deps)


def _from_requirements(path: str, num: int, line: str) -> list[Dependency]:
    line = line.split(" #", 1)[0].strip()
    if not line or line.startswith(("#", "-", "git+", "http:", "https:", "file:", ".", "/")):
        return []  # comments, -r/-e/--index-url options, URLs, local paths
    m = REQ_RE.match(line)
    return [Dependency("pypi", m.group(1), path, num, "manifest", m.group(1))] if m else []


def _from_python(path: str, num: int, line: str, local: set[str]) -> list[Dependency]:
    roots: list[str] = []
    m = PY_FROM_RE.match(line)
    if m:
        roots.append(m.group(1))
    else:
        m = PY_IMPORT_RE.match(line)
        if m:
            roots += [part.split(" as ")[0].strip() for part in m.group(1).split(",")]
    out = []
    for mod in roots:
        if mod.startswith("."):
            continue  # relative import: always the project's own code
        top = mod.split(".")[0]
        if top in PY_STDLIB or top in PY_NAMESPACE_ROOTS or top in local:
            continue
        pkg = IMPORT_TO_PYPI.get(top, top)
        out.append(Dependency("pypi", pkg, path, num, "import", top))
    return out


def _from_js(path: str, num: int, line: str, local: set[str] = frozenset(),
             workspace: set[str] = frozenset()) -> list[Dependency]:
    out = []
    for rx in JS_IMPORT_RES:
        for spec in rx.findall(line):
            name = _npm_package_name(spec)
            if not name or _in_workspace(name, workspace):
                continue
            scope = name[1:].split("/")[0] if name.startswith("@") else None
            if scope and scope in local and scope not in KNOWN_NPM_SCOPES:
                continue  # "@components/x" with a components/ folder: a path alias
            out.append(Dependency("npm", name, path, num, "import", spec))
    return out


def _npm_package_name(spec: str) -> str | None:
    if spec.startswith((".", "/", "~/", "@/", "#")) or "://" in spec:
        return None
    if re.match(r"^[a-z]+:", spec):
        return None  # runtime/bundler prefixes: node:fs, bun:test, virtual:x, npm:x
    parts = spec.split("/")
    if spec.startswith("@"):
        name = "/".join(parts[:2]) if len(parts) >= 2 else None
    elif parts[0] in NODE_BUILTINS:
        return None
    else:
        name = parts[0]
    return name if name and NPM_NAME_RE.match(name) else None


def _in_workspace(name: str, workspace: set[str]) -> bool:
    """Is this one of the repo's own packages? Matches "@acme/db" by full
    name, or by its folder name ("db") when we only know folder names."""
    return name in workspace or name.rsplit("/", 1)[-1] in workspace


def _dedupe(deps: list[Dependency]) -> list[Dependency]:
    """One entry per package; prefer the manifest line (it's what gets installed)."""
    best: dict[tuple[str, str], Dependency] = {}
    for d in deps:
        key = (d.ecosystem, normalize(d.name))
        if key not in best or (d.source == "manifest" and best[key].source != "manifest"):
            best[key] = d
    return list(best.values())


def find_local_modules(repo_root: str, files: list[FileDiff],
                       repo_files: list[str] | None = None) -> set[str]:
    """Names the project defines itself, so `import utils` isn't flagged.

    Looks at the diff's own paths, plus either a list of the repo's files
    (repo_files) or, if not given, the repo on disk.
    """
    names: set[str] = set()
    for f in files:
        parts = f.path.split("/")
        names.update(p for p in parts[:-1])
        names.add(os.path.splitext(parts[-1])[0])
    if repo_files is not None:
        for path in repo_files:
            parts = path.split("/")
            if any(p in SKIP_DIRS or p.startswith(".") for p in parts[:-1]):
                continue
            names.update(parts[:-1][:4])  # same depth limit as the walk below
            if parts[-1].endswith(".py") and len(parts) <= 5:
                names.add(parts[-1][:-3])
    elif os.path.isdir(repo_root):
        root_depth = repo_root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            if dirpath.count(os.sep) - root_depth >= 4:
                dirnames[:] = []
            names.update(dirnames)
            names.update(fn[:-3] for fn in filenames if fn.endswith(".py"))
    return names


def find_workspace_packages(repo_root: str, files: list[FileDiff],
                            repo_files: list[str] | None = None) -> set[str]:
    """npm packages that live inside this repo (monorepo workspaces).

    On disk we read each package.json's "name". With only a file list we
    use the folder name, since workspaces are usually named after their folder.
    """
    names: set[str] = set()
    paths = list(repo_files or []) + [f.path for f in files]
    for path in paths:
        if path == "package.json" or path.endswith("/package.json"):
            if "node_modules/" not in path and "/" in path:
                names.add(path.split("/")[-2])
    if repo_files is None and os.path.isdir(repo_root):
        root_depth = repo_root.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(repo_root):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
            if dirpath.count(os.sep) - root_depth >= 4:
                dirnames[:] = []
            if "package.json" in filenames and dirpath != repo_root:
                names.add(os.path.basename(dirpath))
                try:
                    with open(os.path.join(dirpath, "package.json"), encoding="utf-8") as fh:
                        name = json.load(fh).get("name")
                    if isinstance(name, str):
                        names.add(name)
                except (OSError, ValueError):
                    pass
    return names


# ------------------------------------------------------------------ the check

def check_packages(files: list[FileDiff], registry: Registry | None,
                   repo_root: str = ".", now: datetime | None = None,
                   repo_files: list[str] | None = None,
                   new_package_days: int = NEW_PACKAGE_DAYS,
                   is_allowed: Callable[[str], bool] = lambda name: False,
                   ) -> tuple[list[Finding], list[str]]:
    """Returns (findings, notes). Notes are things we couldn't verify.

    is_allowed: packages the project vouches for (allow_packages in the
    config), e.g. private ones that public registries have never heard of.
    """
    deps = extract_dependencies(files, find_local_modules(repo_root, files, repo_files),
                                find_workspace_packages(repo_root, files, repo_files))
    to_lookup = [d for d in deps if normalize(d.name) not in POPULAR[d.ecosystem]
                 and not is_allowed(d.name)]

    infos: dict[Dependency, PackageInfo] = {}
    if registry is not None and to_lookup:
        with ThreadPoolExecutor(max_workers=8) as pool:  # look up in parallel
            for d, info in zip(to_lookup, pool.map(lambda d: registry.lookup(d.ecosystem, d.name), to_lookup)):
                infos[d] = info

    findings: list[Finding] = []
    notes: list[str] = []
    for d in to_lookup:
        info = infos.get(d)
        f = _judge(d, info, now, new_package_days)
        if f:
            findings.append(f)
        elif info is not None and info.exists is None:
            notes.append(f"Couldn't verify {d.ecosystem} package '{d.name}': {info.error}")
    if registry is None and to_lookup:
        notes.append(f"Offline mode: {len(to_lookup)} package(s) only checked for typos, not existence.")
    return findings, notes


def _judge(d: Dependency, info: PackageInfo | None, now: datetime | None,
           new_package_days: int) -> Finding | None:
    reg = "PyPI" if d.ecosystem == "pypi" else "npm"
    near = closest(d.name, POPULAR[d.ecosystem])
    hint = f' Did you mean "{near[0]}"?' if near else ""
    manifest = d.source == "manifest"

    if info is not None and info.exists is False:
        if manifest:
            return Finding("package.not-found", Severity.HIGH, d.file, d.line,
                           f'"{d.name}" does not exist on {reg}. This is a classic AI-hallucinated '
                           f"dependency, and anyone could register the name and fill it with malware.",
                           f"Remove it or replace it with the real package.{hint}")
        return Finding("package.not-found", Severity.MEDIUM, d.file, d.line,
                       f'Imports "{d.as_written}", but no package called "{d.name}" exists on {reg}.',
                       f"Check that this module really exists (it may be hallucinated) "
                       f"or that it's part of your project.{hint}")

    if info is not None and info.malware_removed:
        return Finding("package.malware-removed", Severity.HIGH, d.file, d.line,
                       f'"{d.name}" was taken down by npm for containing malware.',
                       "Remove it immediately and check whether it was ever installed.")

    age = info.age_days(now) if info else None
    is_new = age is not None and age < new_package_days

    if near:
        sev = Severity.HIGH if is_new else Severity.MEDIUM
        age_txt = f", and it was first published only {age} day(s) ago" if is_new else ""
        return Finding("package.typosquat", sev, d.file, d.line,
                       f'"{d.name}" is one typo away from the popular package "{near[0]}"{age_txt}. '
                       f"Look-alike names are a common way to sneak in malware.",
                       f'Confirm you meant "{d.name}" and not "{near[0]}".')
    if is_new:
        return Finding("package.new", Severity.MEDIUM, d.file, d.line,
                       f'"{d.name}" was first published on {reg} only {age} day(s) ago '
                       f"({info.release_count} release(s)). Attackers register names that AI tools "
                       f"hallucinate, so brand-new packages deserve a look.",
                       "Check the package's source and maintainer before installing it.")
    return None
