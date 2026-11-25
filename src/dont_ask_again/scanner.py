"""Find agent config files, scan them, run the repo checks."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from . import checks, git
from .detect import Detector, Hit, mask
from .rules import RulePack, load_rules

# (parent dir, file name) pairs that are agent config files
AGENT_FILES = {
    (".claude", "settings.local.json"),
    (".claude", "settings.json"),
    (".cursor", "mcp.json"),
    (".vscode", "mcp.json"),
    (".gemini", "settings.json"),
    (".windsurf", "mcp.json"),
}
AGENT_FILE_NAMES = {".mcp.json"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}

HISTORY_PATHSPECS = [f":(glob)**/{d}/{n}" for d, n in sorted(AGENT_FILES)] + [
    f":(glob)**/{n}" for n in sorted(AGENT_FILE_NAMES)
]

RULE_WRAPPER_RE = re.compile(r"^\s*[A-Za-z][\w.-]*\((.*)\)\s*$", re.S)  # Bash(...), WebFetch(...)
PERMISSION_KEYS = {"allow", "deny", "ask"}
SEVERITY_ORDER = {"error": 0, "warn": 1}

CHECKS = {
    "DAA001": "Agent local settings file is tracked by git",
    "DAA002": "Literal secret saved in agent config",
    "DAA003": "Agent config is not ignored by the repo itself",
    "DAA004": "npm package would publish agent config",
}


@dataclass
class Finding:
    check: str
    rule: str
    severity: str  # "error" | "warn"
    file: str
    message: str
    line: int | None = None
    location: str = ""
    snippet: str = ""
    commit: str | None = None
    fingerprint: str = ""
    raw: str = field(default="", repr=False)  # original value, never printed

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw")
        return d


@dataclass
class ScanResult:
    root: Path
    repo: Path | None
    files: list[str]
    findings: list[Finding]
    notes: list[str]

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "error"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "warn"]


# -- file discovery -------------------------------------------------------------


def is_agent_file(relpath: str) -> bool:
    parts = PurePosixPath(relpath).parts
    if not parts:
        return False
    if parts[-1] in AGENT_FILE_NAMES:
        return True
    return len(parts) >= 2 and (parts[-2], parts[-1]) in AGENT_FILES


def find_agent_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Return (agent config files, `.claude` directories) under root."""
    files: list[Path] = []
    claude_dirs: list[Path] = []
    if root.is_file():
        return ([root] if is_agent_file(root.as_posix()) else []), []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        if here.name == ".claude":
            claude_dirs.append(here)
        for name in sorted(filenames):
            p = here / name
            if is_agent_file(p.as_posix()):
                files.append(p)
    return files, claude_dirs


# -- JSON scanning --------------------------------------------------------------


def unwrap_rule(rule: str) -> str:
    """`Bash(npm run test:*)` -> `npm run test`."""
    m = RULE_WRAPPER_RE.match(rule)
    inner = m.group(1) if m else rule
    inner = inner.strip()
    for suffix in (":*", " *", "*"):
        if inner.endswith(suffix):
            inner = inner[: -len(suffix)].rstrip()
            break
    return inner


def _line_of(text: str, value: str, secret: str) -> int | None:
    for needle in (
        json.dumps(value, ensure_ascii=False)[1:-1],
        json.dumps(value)[1:-1],
        secret,
    ):
        if needle:
            idx = text.find(needle)
            if idx >= 0:
                return text.count("\n", 0, idx) + 1
    return None


def _fingerprint(file: str, rule: str, value: str, secret: str) -> str:
    # Hash the value with the secret removed, so the fingerprint never encodes the secret.
    basis = f"{file}|{rule}|{value.replace(secret, '<SECRET>')}"
    return hashlib.sha256(basis.encode()).hexdigest()[:12]


def scan_json_text(text: str, relpath: str, det: Detector) -> list[Finding]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def emit(hits: list[Hit], location: str, value: str) -> None:
        for h in hits:
            key = (location, h.secret)
            if key in seen:
                continue
            seen.add(key)
            snippet = value.replace(h.secret, mask(h.secret))
            if len(snippet) > 200:
                snippet = snippet[:197] + "..."
            findings.append(
                Finding(
                    check="DAA002",
                    rule=h.rule_id,
                    severity="error",
                    file=relpath,
                    line=_line_of(text, value, h.secret),
                    location=location,
                    snippet=snippet,
                    message=h.message,
                    fingerprint=_fingerprint(relpath, h.rule_id, value, h.secret),
                    raw=value,
                )
            )

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}.{k}" if path else str(k)
                if k == "env" and isinstance(v, dict):
                    for name, val in v.items():
                        if isinstance(val, str):
                            hits = det.scan_text(val)
                            h = det.env_value(str(name), val, in_command=False)
                            if h:
                                hits.append(h)
                            emit(hits, f"{p}.{name}", f"{name}={val}")
                elif k == "headers" and isinstance(v, dict):
                    for name, val in v.items():
                        if isinstance(val, str):
                            line = f"{name}: {val}"
                            emit(det.scan_text(line), f"{p}.{name}", line)
                elif k in PERMISSION_KEYS and isinstance(v, list):
                    for i, item in enumerate(v):
                        if isinstance(item, str):
                            emit(det.scan_command(unwrap_rule(item)), f"{p}[{i}]", item)
                        else:
                            walk(item, f"{p}[{i}]")
                elif k == "args" and isinstance(v, list) and all(isinstance(x, str) for x in v):
                    joined = shlex.join(v)
                    emit(det.scan_command(joined), p, joined)
                elif k == "command" and isinstance(v, str):
                    emit(det.scan_command(v), p, v)
                else:
                    walk(v, p)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
        elif isinstance(node, str):
            emit(det.scan_text(node), path, node)

    walk(data, "")
    return findings


# -- history --------------------------------------------------------------------


def scan_history(repo: Path, det: Detector) -> tuple[list[Finding], dict[str, str]]:
    """Scan every committed version of every agent config file.

    Returns (findings, {settings.local.json path: oldest commit that had it}).
    """
    p = git.run(repo, "log", "--all", "--format=%x00%H", "--name-only", "--diff-filter=AMR", "--", *HISTORY_PATHSPECS, timeout=600)
    if p.returncode != 0:
        return [], {}
    by_fp: dict[str, Finding] = {}
    past_local: dict[str, str] = {}
    for chunk in p.stdout.split("\0"):
        lines = [ln for ln in chunk.splitlines() if ln.strip()]
        if not lines:
            continue
        commit, paths = lines[0].strip(), lines[1:]
        for path in paths:
            if not is_agent_file(path):
                continue
            blob = git.run(repo, "show", f"{commit}:{path}")
            if blob.returncode != 0:
                continue
            for f in scan_json_text(blob.stdout, path, det):
                f.commit = commit[:12]
                by_fp[f.fingerprint] = f  # log is newest-first: the last write is the oldest commit
            if PurePosixPath(path).name == "settings.local.json":
                past_local[path] = commit[:12]
    return list(by_fp.values()), past_local


# -- orchestration --------------------------------------------------------------


def _rel(p: Path, base: Path) -> str:
    try:
        return p.resolve().relative_to(base).as_posix()
    except ValueError:
        return p.as_posix()


def load_ignores(root: Path) -> set[str]:
    f = root / ".daaignore"
    if not f.is_file():
        return set()
    out = set()
    for line in f.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def scan(
    path: str | Path = ".",
    rules: RulePack | None = None,
    history: bool = False,
    git_checks: bool = True,
    skip: set[str] | None = None,
) -> ScanResult:
    root = Path(path).resolve()
    det = Detector(rules or load_rules())
    skip = skip or set()
    repo = git.repo_root(root)
    base = repo or (root if root.is_dir() else root.parent)
    notes: list[str] = []

    files, claude_dirs = find_agent_files(root)
    findings: list[Finding] = []

    for f in files:
        rel = _rel(f, base)
        file_findings = scan_json_text(f.read_text(encoding="utf-8", errors="replace"), rel, det)
        if file_findings and repo and not git.is_tracked(repo, rel):
            ignored, _ = git.check_ignore(repo, rel)
            if ignored:
                # Only on this machine. Still plain text on disk, but not about to leak via git.
                for ff in file_findings:
                    ff.severity = "warn"
                    ff.message += " (local only: this file is untracked and git-ignored, but the secret is still in plain text on disk)"
        findings += file_findings

    if repo and git_checks:
        findings += checks.tracked_local_settings(repo)
        claude_rel = [_rel(d, repo) for d in claude_dirs]
        findings += checks.ignore_travels(repo, claude_rel)
        findings += checks.dockerignore(repo, bool(claude_dirs))
        npm_findings, npm_notes = checks.npm_pack(repo, bool(claude_dirs) and "DAA004" not in skip)
        findings += npm_findings
        notes += npm_notes
    elif git_checks and not repo:
        notes.append("not a git repository: skipped DAA001, DAA003 and DAA004")

    if history:
        if repo:
            current = {f.fingerprint for f in findings}
            hist, past_local = scan_history(repo, det)
            for f in hist:
                if f.fingerprint in current:
                    continue
                f.message = f"In git history (commit {f.commit}), still readable by anyone with a clone or fork. {f.message}"
                findings.append(f)
            tracked_now = {f.file for f in findings if f.check == "DAA001"}
            for p, commit in sorted(past_local.items()):
                if p not in tracked_now:
                    findings.append(
                        Finding(
                            check="DAA001",
                            rule="local-settings-in-history",
                            severity="warn",
                            file=p,
                            commit=commit,
                            message=f"Was committed in the past (commit {commit}). It is still in git history and in every clone and fork.",
                            fingerprint=hashlib.sha256(f"hist|{p}".encode()).hexdigest()[:12],
                        )
                    )
        else:
            notes.append("--history needs a git repository: skipped")

    findings = [f for f in findings if f.check not in skip]
    ignores = load_ignores(repo or base)
    if ignores:
        before = len(findings)
        findings = [f for f in findings if f.fingerprint not in ignores]
        if before != len(findings):
            notes.append(f"{before - len(findings)} finding(s) suppressed by .daaignore")

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.file, f.line or 0))
    return ScanResult(root=root, repo=repo, files=[_rel(f, base) for f in files], findings=findings, notes=notes)
