"""Repo-level checks: DAA001 (tracked), DAA003 (ignores travel), DAA004 (npm)."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from . import git

if TYPE_CHECKING:
    from .scanner import Finding


def _finding(**kw) -> "Finding":
    from .scanner import Finding

    kw.setdefault("fingerprint", hashlib.sha256(f"{kw['check']}|{kw['rule']}|{kw['file']}".encode()).hexdigest()[:12])
    return Finding(**kw)


def tracked_local_settings(repo: Path) -> list["Finding"]:
    out = []
    for p in git.tracked(repo, [":(glob)**/.claude/settings.local.json"]):
        out.append(
            _finding(
                check="DAA001",
                rule="local-settings-tracked",
                severity="error",
                file=p,
                message=(
                    "Personal Claude Code settings are committed. Every approved command in it, "
                    "including any typed password, is readable by anyone with repo access. "
                    "Rotate any secret it ever held, then run `dont-ask-again fix`."
                ),
            )
        )
    return out


def ignore_travels(repo: Path, claude_dirs: list[str]) -> list["Finding"]:
    """Claude Code only adds settings.local.json to the user's *global* git excludes."""
    out = []
    for d in sorted(set(claude_dirs)):
        rel = f"{d}/settings.local.json" if d not in ("", ".") else ".claude/settings.local.json"
        ignored, source = git.check_ignore(repo, rel)
        if not ignored:
            out.append(
                _finding(
                    check="DAA003",
                    rule="gitignore-missing",
                    severity="warn",
                    file=rel,
                    message="Not ignored at all: `git add .` would commit it. Add `**/.claude/settings.local.json` to the repo's .gitignore.",
                )
            )
        elif not git.source_travels(source):
            out.append(
                _finding(
                    check="DAA003",
                    rule="gitignore-global-only",
                    severity="warn",
                    file=rel,
                    message=(
                        f"Ignored only by {source}, which exists on this machine only. Other clones, "
                        "CI, npm packs and Docker builds don't see that rule. Add "
                        "`**/.claude/settings.local.json` to the repo's own .gitignore."
                    ),
                )
            )
    return out


def _dockerignore_covers(path: Path) -> bool:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        norm = line.lstrip("/")
        if norm.startswith("**/"):
            norm = norm[3:]
        norm = norm.rstrip("/")
        if norm in ("*", "**", ".*", ".claude", ".claude/*", ".claude/**", ".claude/settings.local.json"):
            return True
    return False


def dockerignore(repo: Path, has_claude: bool) -> list["Finding"]:
    if not has_claude:
        return []
    has_dockerfile = any(repo.glob("Dockerfile*")) or any(repo.glob("*.Dockerfile")) or (repo / "Containerfile").exists()
    di = repo / ".dockerignore"
    if di.exists():
        if _dockerignore_covers(di):
            return []
        msg = ".dockerignore does not exclude .claude/, so `COPY . .` puts agent settings into the image. Add `**/.claude`."
    elif has_dockerfile:
        msg = "Dockerfile without .dockerignore: `COPY . .` puts agent settings into the image. Create .dockerignore with `**/.claude`."
    else:
        return []
    return [_finding(check="DAA003", rule="dockerignore-missing", severity="warn", file=".dockerignore", message=msg)]


def npm_pack(repo: Path, enabled: bool) -> tuple[list["Finding"], list[str]]:
    if not enabled or not (repo / "package.json").is_file():
        return [], []
    npm = shutil.which("npm")
    if not npm:
        return [], ["npm not found: skipped DAA004 (would the npm package ship .claude/?)"]
    try:
        p = subprocess.run(
            [npm, "pack", "--dry-run", "--json", "--ignore-scripts"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=120,
        )
        data = json.loads(p.stdout or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return [], [f"npm pack --dry-run failed ({type(e).__name__}): skipped DAA004"]
    shipped = sorted(
        f["path"]
        for pkg in data
        for f in pkg.get("files", [])
        if f.get("path", "").startswith(".claude/") or "/.claude/" in f.get("path", "")
    )
    if not shipped:
        return [], []
    return [
        _finding(
            check="DAA004",
            rule="npm-ships-agent-config",
            severity="error",
            file="package.json",
            snippet=", ".join(shipped),
            message="`npm publish` would ship agent config: " + ", ".join(shipped) + ". Add `.claude/` to .npmignore or use a `files` allow-list in package.json.",
        )
    ], []
