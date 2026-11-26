"""Find agent config files, scan them, run the repo checks."""

from __future__ import annotations

import json
import os
import re
import shlex
import tomllib
from pathlib import Path, PurePosixPath

from . import checks, git
from .detect import Detector, Hit, mask
from .models import CHECKS, GIT_CHECKS, SEVERITY_ORDER, Finding, ScanResult, fingerprint
from .rules import RulePack, load_rules

__all__ = ["CHECKS", "Finding", "ScanResult", "scan", "scan_config_text", "scan_json_text", "unwrap_rule"]

# (parent dir, file name) pairs that are agent config files
AGENT_FILES = {
    (".claude", "settings.local.json"),
    (".claude", "settings.json"),
    (".cursor", "mcp.json"),
    (".vscode", "mcp.json"),
    (".gemini", "settings.json"),
    (".windsurf", "mcp.json"),
    (".codex", "config.toml"),
}
AGENT_FILE_NAMES = {".mcp.json"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache"}

HISTORY_PATHSPECS = [f":(glob)**/{d}/{n}" for d, n in sorted(AGENT_FILES)] + [
    f":(glob)**/{n}" for n in sorted(AGENT_FILE_NAMES)
]

RULE_WRAPPER_RE = re.compile(r"^\s*[A-Za-z][\w.-]*\((.*)\)\s*$", re.S)  # Bash(...), WebFetch(...)
PERMISSION_KEYS = {"allow", "deny", "ask"}
HEADER_KEYS = {"headers", "http_headers"}  # Claude/Cursor MCP, Codex
LOCAL_ONLY_NOTE = " (local only: this file is untracked and git-ignored, but the secret is still in plain text on disk)"


# -- file discovery -------------------------------------------------------------


def is_agent_file(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not parts:
        return False
    return parts[-1] in AGENT_FILE_NAMES or (len(parts) >= 2 and (parts[-2], parts[-1]) in AGENT_FILES)


def find_agent_files(root: Path) -> tuple[list[Path], list[Path]]:
    """Return (agent config files, `.claude` directories) under root."""
    if root.is_file():
        return ([root] if is_agent_file(root.as_posix()) else []), []
    files: list[Path] = []
    claude_dirs: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        here = Path(dirpath)
        if here.name == ".claude":
            claude_dirs.append(here)
        files += [here / n for n in sorted(filenames) if is_agent_file((here / n).as_posix())]
    return files, claude_dirs


# -- JSON scanning --------------------------------------------------------------


def unwrap_rule(rule: str) -> str:
    """`Bash(npm run test:*)` -> `npm run test`."""
    m = RULE_WRAPPER_RE.match(rule)
    inner = (m.group(1) if m else rule).strip()
    for suffix in (":*", " *", "*"):
        if inner.endswith(suffix):
            return inner[: -len(suffix)].rstrip()
    return inner


def _line_of(text: str, value: str, secret: str) -> int | None:
    for needle in (json.dumps(value, ensure_ascii=False)[1:-1], json.dumps(value)[1:-1], secret):
        idx = text.find(needle) if needle else -1
        if idx >= 0:
            return text.count("\n", 0, idx) + 1
    return None


def scan_config_text(text: str, relpath: str, det: Detector) -> list[Finding]:
    """Scan one agent config file (JSON, or TOML for `.toml` paths)."""
    try:
        data = tomllib.loads(text) if relpath.endswith(".toml") else json.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()

    def emit(hits: list[Hit], location: str, value: str) -> None:
        for h in hits:
            if (location, h.secret) in seen:
                continue
            seen.add((location, h.secret))
            snippet = value.replace(h.secret, mask(h.secret))
            findings.append(
                Finding(
                    check="DAA002",
                    rule=h.rule_id,
                    severity="error",
                    file=relpath,
                    line=_line_of(text, value, h.secret),
                    location=location,
                    snippet=snippet if len(snippet) <= 200 else snippet[:197] + "...",
                    message=h.message,
                    # The secret is replaced before hashing, so the fingerprint never encodes it.
                    fingerprint=fingerprint(relpath, h.rule_id, value.replace(h.secret, "<SECRET>")),
                    raw=value,
                    secret=h.secret,
                )
            )

    def walk(node, path: str) -> None:
        if isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")
        elif isinstance(node, str):
            emit(det.scan_text(node), path, node)
        elif isinstance(node, dict):
            for k, v in node.items():
                p = f"{path}.{k}" if path else str(k)
                if k == "env" and isinstance(v, dict):
                    for name, val in v.items():
                        if isinstance(val, str):
                            h = det.env_value(str(name), val, in_command=False)
                            emit(det.scan_text(val) + ([h] if h else []), f"{p}.{name}", f"{name}={val}")
                elif k in HEADER_KEYS and isinstance(v, dict):
                    for name, val in v.items():
                        if isinstance(val, str):
                            emit(det.scan_text(f"{name}: {val}"), f"{p}.{name}", f"{name}: {val}")
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
                elif isinstance(v, str):
                    # A key named like a secret (`bearer_token = "..."`, `"api_key": "..."`)
                    h = det.env_value(str(k), v, in_command=False)
                    emit(det.scan_text(v) + ([h] if h else []), p, v)
                else:
                    walk(v, p)

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

    versions: list[tuple[str, str]] = []  # (commit, path), newest first
    for chunk in p.stdout.split("\0"):
        lines = [ln for ln in chunk.splitlines() if ln.strip()]
        if lines:
            versions += [(lines[0].strip(), path) for path in lines[1:] if is_agent_file(path)]

    # One `git cat-file --batch` process for every version, instead of one `git show` each.
    blobs = git.read_blobs(repo, [f"{c}:{path}" for c, path in versions])

    by_key: dict[tuple[str, str, str], Finding] = {}
    seen_in: dict[tuple[str, str, str], int] = {}
    past_local: dict[str, str] = {}
    for commit, path in versions:
        text = blobs.get(f"{commit}:{path}")
        if text is None:
            continue
        for f in scan_config_text(text, path, det):
            f.commit = commit[:12]
            by_key[f.dedupe_key] = f  # newest-first, so the last write is the oldest commit
            seen_in[f.dedupe_key] = seen_in.get(f.dedupe_key, 0) + 1
        if PurePosixPath(path).name == "settings.local.json":
            past_local[path] = commit[:12]

    for key, f in by_key.items():
        n = seen_in[key]
        f.message = (
            f"In git history (first in commit {f.commit}"
            + (f", present in {n} commits" if n > 1 else "")
            + f"), still readable by anyone with a clone or fork. {f.message}"
        )
    return list(by_key.values()), past_local


# -- orchestration --------------------------------------------------------------


def _rel(p: Path, base: Path) -> str:
    try:
        return p.resolve().relative_to(base).as_posix()
    except ValueError:
        return p.as_posix()


def _mark_local_only(repo: Path, findings: list[Finding]) -> None:
    """Downgrade secrets in files that are untracked and git-ignored: they stay on this machine."""
    files = sorted({f.file for f in findings if f.check == "DAA002"})
    tracked = git.tracked(repo, [f":(literal){p}" for p in files])
    sources = git.ignore_sources(repo, [p for p in files if p not in tracked])
    local_only = {p for p, src in sources.items() if src is not None}
    for f in findings:
        if f.check == "DAA002" and f.file in local_only:
            f.severity = "warn"
            f.message += LOCAL_ONLY_NOTE


def _git_checks(repo: Path, claude_dirs: list[str], skip: set[str], notes: list[str]) -> list[Finding]:
    out: list[Finding] = []
    if "DAA001" not in skip:
        out += checks.tracked_local_settings(repo)
    if claude_dirs and "DAA003" not in skip:
        out += checks.ignore_travels(repo, claude_dirs) + checks.dockerignore(repo)
    if claude_dirs and "DAA004" not in skip:
        npm_findings, npm_notes = checks.npm_pack(repo)
        out += npm_findings
        notes += npm_notes
    return out


def _history_findings(repo: Path, det: Detector, current: list[Finding]) -> list[Finding]:
    current_keys = {f.dedupe_key for f in current}
    hist, past_local = scan_history(repo, det)
    out = [f for f in hist if f.dedupe_key not in current_keys]
    tracked_now = {f.file for f in current if f.check == "DAA001"}
    out += [
        Finding(
            check="DAA001",
            rule="local-settings-in-history",
            severity="warn",
            file=p,
            commit=commit,
            message=f"Was committed in the past (commit {commit}). It is still in git history and in every clone and fork.",
        )
        for p, commit in sorted(past_local.items())
        if p not in tracked_now
    ]
    return out


def _apply_ignores(findings: list[Finding], root: Path, notes: list[str]) -> list[Finding]:
    f = root / ".daaignore"
    if not f.is_file():
        return findings
    ignores = {ln.split("#", 1)[0].strip() for ln in f.read_text(encoding="utf-8").splitlines()} - {""}
    kept = [x for x in findings if x.fingerprint not in ignores]
    if len(kept) != len(findings):
        notes.append(f"{len(findings) - len(kept)} finding(s) suppressed by .daaignore")
    return kept


def scan(
    path: str | Path = ".",
    rules: RulePack | None = None,
    history: bool = False,
    skip: set[str] | frozenset[str] = frozenset(),
) -> ScanResult:
    root = Path(path).resolve()
    det = Detector(rules or load_rules())
    skip = {s.upper() for s in skip}
    repo = git.repo_root(root)
    base = repo or (root if root.is_dir() else root.parent)
    notes: list[str] = []

    files, claude_dirs = find_agent_files(root)
    rels = [_rel(f, base) for f in files]
    findings = [x for f, rel in zip(files, rels) for x in scan_config_text(f.read_text(encoding="utf-8", errors="replace"), rel, det)]

    if repo:
        _mark_local_only(repo, findings)
        findings += _git_checks(repo, [_rel(d, repo) for d in claude_dirs], skip, notes)
        if history:
            findings += _history_findings(repo, det, findings)
    else:
        if not GIT_CHECKS <= skip:
            notes.append("not a git repository: skipped DAA001, DAA003 and DAA004")
        if history:
            notes.append("--history needs a git repository: skipped")

    findings = _apply_ignores([f for f in findings if f.check not in skip], repo or base, notes)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.check, f.file, f.line or 0))
    return ScanResult(root=root, repo=repo, files=rels, findings=findings, notes=notes)


scan_json_text = scan_config_text  # v0.1 name, kept for compatibility
