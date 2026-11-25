"""Thin wrappers around the git CLI. Each helper is one git process, however many paths."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def run(repo: Path, *args: str, input: str | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        input=input,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def repo_root(path: Path) -> Path | None:
    if shutil.which("git") is None:
        return None
    p = run(path if path.is_dir() else path.parent, "rev-parse", "--show-toplevel")
    return Path(p.stdout.strip()).resolve() if p.returncode == 0 else None


def tracked(repo: Path, pathspecs: list[str]) -> set[str]:
    if not pathspecs:
        return set()
    p = run(repo, "ls-files", "-z", "--", *pathspecs)
    return {x for x in p.stdout.split("\0") if x} if p.returncode == 0 else set()


def ignore_sources(repo: Path, paths: list[str]) -> dict[str, str | None]:
    """{path: file holding the ignore rule that applies, or None if not ignored}.

    `--no-index` answers even for tracked or missing files. The source tells a repo
    `.gitignore` (travels with the repo) from the global excludes file or
    `.git/info/exclude` (exist on one machine only).
    """
    out: dict[str, str | None] = dict.fromkeys(paths)
    if not paths:
        return out
    p = run(repo, "check-ignore", "-v", "-n", "-z", "--no-index", "--stdin", input="\0".join(paths) + "\0")
    fields = p.stdout.split("\0")  # source, line, pattern, path, source, ...
    for i in range(0, len(fields) - 3, 4):
        source, _line, pattern, path = fields[i : i + 4]
        if source and not pattern.startswith("!"):
            out[path] = source
    return out


def source_travels(source: str | None) -> bool:
    """True if the ignore rule lives in a `.gitignore` committed in the repo."""
    return bool(source) and not os.path.isabs(source) and not source.startswith(".git/") and os.path.basename(source) == ".gitignore"


def read_blobs(repo: Path, specs: list[str], timeout: int = 600) -> dict[str, str]:
    """Read many `<rev>:<path>` objects with one `git cat-file --batch`. Missing ones are left out."""
    if not specs:
        return {}
    p = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input=("\n".join(specs) + "\n").encode(),
        capture_output=True,
        timeout=timeout,
    )
    out: dict[str, str] = {}
    data, pos = p.stdout, 0
    for spec in specs:
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        header = data[pos:nl].decode("utf-8", "replace")
        pos = nl + 1
        if header.endswith((" missing", " ambiguous")):
            continue
        size = int(header.rsplit(" ", 1)[1])  # "<oid> <type> <size>"
        out[spec] = data[pos : pos + size].decode("utf-8", "replace")
        pos += size + 1  # content is followed by a newline
    return out
