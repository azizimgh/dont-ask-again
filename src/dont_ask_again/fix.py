"""`dont-ask-again fix`: plan the safe fixes, apply them only with --yes."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import git
from .scanner import ScanResult

GITIGNORE_BLOCK = (
    "\n# AI agent local settings: may hold approved commands with secrets (added by dont-ask-again)\n"
    "**/.claude/settings.local.json\n"
)
DOCKERIGNORE_BLOCK = "\n# AI agent config (added by dont-ask-again)\n**/.claude\n"
NPMIGNORE_BLOCK = "\n# AI agent config (added by dont-ask-again)\n.claude/\n"
PERMISSION_LOCATION_RE = re.compile(r"(^|\.)(allow|deny|ask)\[\d+\]$")
BACKUP_DIR = Path.home() / ".dont-ask-again" / "backups"


@dataclass
class Action:
    summary: str
    apply: Callable[[], None]


def _append(path: Path, block: str) -> Callable[[], None]:
    def run() -> None:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if block.strip() in existing:
            return
        if not existing:
            path.write_text(block.lstrip("\n"), encoding="utf-8")
            return
        sep = "" if existing.endswith("\n") else "\n"
        path.write_text(existing + sep + block, encoding="utf-8")

    return run


def _untrack(repo: Path, rel: str) -> Callable[[], None]:
    def run() -> None:
        p = git.run(repo, "rm", "--cached", "--quiet", "--", rel)
        if p.returncode != 0:
            raise RuntimeError(f"git rm --cached {rel} failed: {p.stderr.strip()}")

    return run


def _backup(path: Path) -> Path:
    # Outside the repo on purpose: a backup next to the original could get committed.
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR.parent, 0o700)
    os.chmod(BACKUP_DIR, 0o700)
    name = time.strftime("%Y%m%d-%H%M%S-") + re.sub(r"[^A-Za-z0-9._-]", "_", str(path.resolve()).lstrip("/"))
    dest = BACKUP_DIR / name
    dest.write_bytes(path.read_bytes())
    os.chmod(dest, 0o600)
    return dest


def _remove_rules(path: Path, raws: set[str], log: list[str]) -> Callable[[], None]:
    def run() -> None:
        data = json.loads(path.read_text(encoding="utf-8"))
        removed = 0

        def walk(node):
            nonlocal removed
            if isinstance(node, dict):
                for k, v in node.items():
                    if k in ("allow", "deny", "ask") and isinstance(v, list):
                        keep = [x for x in v if not (isinstance(x, str) and x in raws)]
                        removed += len(v) - len(keep)
                        node[k] = keep
                    else:
                        walk(v)
            elif isinstance(node, list):
                for x in node:
                    walk(x)

        walk(data)
        if removed:
            dest = _backup(path)
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            log.append(f"backup of {path.name} saved to {dest} (mode 600). It still holds the secret: delete it once you're happy.")

    return run


def plan(result: ScanResult, redact_local: bool) -> tuple[list[Action], list[str], list[str]]:
    """Return (actions, manual steps, log list that actions append to)."""
    actions: list[Action] = []
    manual: list[str] = []
    log: list[str] = []
    repo = result.repo
    current = [f for f in result.findings if f.commit is None]

    if repo:
        for f in current:
            if f.check == "DAA001" and f.rule == "local-settings-tracked":
                actions.append(Action(f"git rm --cached {f.file}  (keeps your local copy)", _untrack(repo, f.file)))

        if any(f.check == "DAA003" and f.rule.startswith("gitignore") for f in current) or any(
            f.check == "DAA001" and f.rule == "local-settings-tracked" for f in current
        ):
            gi = repo / ".gitignore"
            if "**/.claude/settings.local.json" not in (gi.read_text(encoding="utf-8") if gi.exists() else ""):
                actions.append(Action("add `**/.claude/settings.local.json` to .gitignore", _append(gi, GITIGNORE_BLOCK)))

        if any(f.rule == "dockerignore-missing" for f in current):
            actions.append(Action("add `**/.claude` to .dockerignore", _append(repo / ".dockerignore", DOCKERIGNORE_BLOCK)))

        if any(f.check == "DAA004" for f in current):
            npmignore = repo / ".npmignore"
            if npmignore.exists():
                actions.append(Action("add `.claude/` to .npmignore", _append(npmignore, NPMIGNORE_BLOCK)))
            else:
                manual.append(
                    "npm would publish .claude/. Add a `files` allow-list to package.json, or create .npmignore "
                    "with `.claude/` (note: once .npmignore exists, npm stops reading .gitignore, so copy its rules over)."
                )

    secret_rules: dict[str, set[str]] = {}
    base = repo or (result.root if result.root.is_dir() else result.root.parent)
    for f in current:
        if f.check != "DAA002":
            continue
        if PERMISSION_LOCATION_RE.search(f.location) and "/.claude/" in "/" + f.file:
            secret_rules.setdefault(f.file, set()).add(f.raw)
        else:
            manual.append(f"{f.file} {f.location}: move the literal value into an environment variable or secret manager.")

    for rel, raws in sorted(secret_rules.items()):
        if redact_local:
            actions.append(
                Action(
                    f"remove {len(raws)} secret-bearing permission rule(s) from {rel} "
                    "(Claude Code will ask again next time)",
                    _remove_rules(base / rel, raws, log),
                )
            )
        else:
            manual.append(f"{rel}: {len(raws)} permission rule(s) hold a secret. Re-run with --redact-local to remove them.")

    if any(f.commit for f in result.findings) or any(f.rule == "local-settings-in-history" for f in result.findings):
        manual.append(
            "Secrets are in git history. Rotate them; that is the real fix. Rewriting history "
            "(e.g. `git filter-repo --invert-paths --path .claude/settings.local.json`) does not reach "
            "existing clones or forks, and it needs a force-push your team must agree to."
        )

    if any(f.check == "DAA002" for f in result.findings):
        manual.insert(0, "Rotate every credential listed by `dont-ask-again scan` before anything else.")

    return actions, manual, log
