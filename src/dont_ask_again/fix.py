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
from .checks import IGNORE_LINE
from .models import ScanResult

GITIGNORE_BLOCK = f"# AI agent local settings: may hold approved commands with secrets (added by dont-ask-again)\n{IGNORE_LINE}\n"
DOCKERIGNORE_BLOCK = "# AI agent config (added by dont-ask-again)\n**/.claude\n"
NPMIGNORE_BLOCK = "# AI agent config (added by dont-ask-again)\n.claude/\n"
PERMISSION_LOCATION_RE = re.compile(r"(^|\.)(allow|deny|ask)\[\d+\]$")
BACKUP_DIR = Path.home() / ".dont-ask-again" / "backups"


@dataclass
class Action:
    summary: str
    apply: Callable[[], str | None]  # returns an optional message for the user


def _append(path: Path, block: str) -> Callable[[], None]:
    def run() -> None:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        if block.strip() in existing:
            return
        sep = "\n" if existing and not existing.endswith("\n") else ""
        path.write_text(existing + sep + ("\n" if existing else "") + block, encoding="utf-8")

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
    for d in (BACKUP_DIR.parent, BACKUP_DIR):
        os.chmod(d, 0o700)
    dest = BACKUP_DIR / (time.strftime("%Y%m%d-%H%M%S-") + re.sub(r"[^A-Za-z0-9._-]", "_", str(path.resolve()).lstrip("/")))
    dest.write_bytes(path.read_bytes())
    os.chmod(dest, 0o600)
    return dest


def _remove_rules(path: Path, raws: set[str]) -> Callable[[], str | None]:
    def run() -> str | None:
        data = json.loads(path.read_text(encoding="utf-8"))
        removed = 0

        def walk(node) -> None:
            nonlocal removed
            if isinstance(node, list):
                for x in node:
                    walk(x)
            elif isinstance(node, dict):
                for k, v in node.items():
                    if k in ("allow", "deny", "ask") and isinstance(v, list):
                        node[k] = [x for x in v if not (isinstance(x, str) and x in raws)]
                        removed += len(v) - len(node[k])
                    else:
                        walk(v)

        walk(data)
        if not removed:
            return None
        dest = _backup(path)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return f"backup of {path.name} saved to {dest} (mode 600). It still holds the secret: delete it once you're happy."

    return run


def plan(result: ScanResult, redact_local: bool) -> tuple[list[Action], list[str]]:
    """Return (actions to apply, steps the user must do by hand)."""
    actions: list[Action] = []
    manual: list[str] = []
    repo = result.repo
    current = [f for f in result.findings if f.commit is None]
    rules = {(f.check, f.rule) for f in current}

    if repo:
        for f in current:
            if f.rule == "local-settings-tracked":
                actions.append(Action(f"git rm --cached {f.file}  (keeps your local copy)", _untrack(repo, f.file)))

        gi = repo / ".gitignore"
        needs_gitignore = any(c == "DAA003" and r.startswith("gitignore") or r == "local-settings-tracked" for c, r in rules)
        if needs_gitignore and IGNORE_LINE not in (gi.read_text(encoding="utf-8") if gi.exists() else ""):
            actions.append(Action(f"add `{IGNORE_LINE}` to .gitignore", _append(gi, GITIGNORE_BLOCK)))

        if ("DAA003", "dockerignore-missing") in rules:
            actions.append(Action("add `**/.claude` to .dockerignore", _append(repo / ".dockerignore", DOCKERIGNORE_BLOCK)))

        if any(c == "DAA004" for c, _ in rules):
            if (repo / ".npmignore").exists():
                actions.append(Action("add `.claude/` to .npmignore", _append(repo / ".npmignore", NPMIGNORE_BLOCK)))
            else:
                manual.append(
                    "npm would publish .claude/. Add a `files` allow-list to package.json, or create .npmignore "
                    "with `.claude/` (note: once .npmignore exists, npm stops reading .gitignore, so copy its rules over)."
                )

    base = repo or (result.root if result.root.is_dir() else result.root.parent)
    secret_rules: dict[str, set[str]] = {}
    for f in current:
        if f.check != "DAA002":
            continue
        if PERMISSION_LOCATION_RE.search(f.location) and "/.claude/" in "/" + f.file:
            secret_rules.setdefault(f.file, set()).add(f.raw)
        else:
            manual.append(f"{f.file} {f.location}: move the literal value into an environment variable or secret manager.")

    for rel, raws in sorted(secret_rules.items()):
        if redact_local:
            summary = f"remove {len(raws)} secret-bearing permission rule(s) from {rel} (Claude Code will ask again next time)"
            actions.append(Action(summary, _remove_rules(base / rel, raws)))
        else:
            manual.append(f"{rel}: {len(raws)} permission rule(s) hold a secret. Re-run with --redact-local to remove them.")

    if any(f.commit for f in result.findings):
        manual.append(
            "Secrets are in git history. Rotate them; that is the real fix. Rewriting history "
            "(e.g. `git filter-repo --invert-paths --path .claude/settings.local.json`) does not reach "
            "existing clones or forks, and it needs a force-push your team must agree to."
        )
    if any(f.check == "DAA002" for f in result.findings):
        manual.insert(0, "Rotate every credential listed by `dont-ask-again scan` before anything else.")
    return actions, manual
