"""Repo-level checks: DAA001 (tracked), DAA003 (ignores travel), DAA004 (npm)."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from . import git
from .models import Finding

LOCAL_SETTINGS_GLOB = ":(glob)**/.claude/settings.local.json"
IGNORE_LINE = "**/.claude/settings.local.json"


def tracked_local_settings(repo: Path) -> list[Finding]:
    return [
        Finding(
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
        for p in sorted(git.tracked(repo, [LOCAL_SETTINGS_GLOB]))
    ]


def ignore_travels(repo: Path, claude_dirs: list[str]) -> list[Finding]:
    """Claude Code only adds settings.local.json to the user's *global* git excludes."""
    paths = sorted({f"{d}/settings.local.json" for d in claude_dirs})
    out = []
    for rel, source in git.ignore_sources(repo, paths).items():
        if source is None:
            rule, msg = "gitignore-missing", f"Not ignored at all: `git add .` would commit it. Add `{IGNORE_LINE}` to the repo's .gitignore."
        elif not git.source_travels(source):
            rule, msg = "gitignore-global-only", (
                f"Ignored only by {source}, which exists on this machine only. Other clones, CI, "
                f"npm packs and Docker builds don't see that rule. Add `{IGNORE_LINE}` to the repo's own .gitignore."
            )
        else:
            continue
        out.append(Finding(check="DAA003", rule=rule, severity="warn", file=rel, message=msg))
    return out


def _dockerignore_covers(path: Path) -> bool:
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line[0] in "#!":
            continue
        norm = line.lstrip("/").removeprefix("**/").rstrip("/")
        if norm in ("*", "**", ".*", ".claude", ".claude/*", ".claude/**", ".claude/settings.local.json"):
            return True
    return False


def dockerignore(repo: Path) -> list[Finding]:
    di = repo / ".dockerignore"
    if di.exists():
        if _dockerignore_covers(di):
            return []
        msg = ".dockerignore does not exclude .claude/, so `COPY . .` puts agent settings into the image. Add `**/.claude`."
    elif any(repo.glob("Dockerfile*")) or any(repo.glob("*.Dockerfile")) or (repo / "Containerfile").exists():
        msg = "Dockerfile without .dockerignore: `COPY . .` puts agent settings into the image. Create .dockerignore with `**/.claude`."
    else:
        return []
    return [Finding(check="DAA003", rule="dockerignore-missing", severity="warn", file=".dockerignore", message=msg)]


def npm_pack(repo: Path) -> tuple[list[Finding], list[str]]:
    if not (repo / "package.json").is_file():
        return [], []
    npm = shutil.which("npm")
    if not npm:
        return [], ["npm not found: skipped DAA004 (would the npm package ship .claude/?)"]
    try:
        p = subprocess.run([npm, "pack", "--dry-run", "--json", "--ignore-scripts"], cwd=repo, capture_output=True, text=True, timeout=120)
        data = json.loads(p.stdout or "[]")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        return [], [f"npm pack --dry-run failed ({type(e).__name__}): skipped DAA004"]
    shipped = sorted(
        path
        for pkg in data
        for f in pkg.get("files", [])
        if (path := f.get("path", "")).startswith(".claude/") or "/.claude/" in path
    )
    if not shipped:
        return [], []
    listed = ", ".join(shipped)
    return [
        Finding(
            check="DAA004",
            rule="npm-ships-agent-config",
            severity="error",
            file="package.json",
            snippet=listed,
            message=f"`npm publish` would ship agent config: {listed}. Add `.claude/` to .npmignore or use a `files` allow-list in package.json.",
        )
    ], []
