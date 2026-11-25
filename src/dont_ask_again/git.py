"""Thin wrappers around the git CLI."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


def available() -> bool:
    return shutil.which("git") is not None


def run(repo: Path, *args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )


def read_blobs(repo: Path, specs: list[str], timeout: int = 600) -> dict[str, str]:
    """Read many `<rev>:<path>` objects with a single `git cat-file --batch` process.

    Missing objects are left out of the result.
    """
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


def repo_root(path: Path) -> Path | None:
    if not available():
        return None
    start = path if path.is_dir() else path.parent
    p = run(start, "rev-parse", "--show-toplevel")
    if p.returncode != 0:
        return None
    return Path(p.stdout.strip()).resolve()


def tracked(repo: Path, pathspecs: list[str]) -> list[str]:
    p = run(repo, "ls-files", "-z", "--", *pathspecs)
    if p.returncode != 0:
        return []
    return [x for x in p.stdout.split("\0") if x]


def is_tracked(repo: Path, relpath: str) -> bool:
    return run(repo, "ls-files", "--error-unmatch", "--", relpath).returncode == 0


def check_ignore(repo: Path, relpath: str) -> tuple[bool, str | None]:
    """Is `relpath` ignored, and by which file?

    `--no-index` gives the answer even for tracked or missing files.
    `-v` tells us the source, so we can tell a repo `.gitignore` (travels with
    the repo) from the global excludes file or `.git/info/exclude` (does not).
    """
    p = run(repo, "check-ignore", "-v", "--no-index", "--", relpath)
    if p.returncode != 0 or not p.stdout.strip():
        return False, None
    line = p.stdout.strip().splitlines()[0]
    meta = line.split("\t", 1)[0]          # source:linenum:pattern
    source = meta.rsplit(":", 2)[0]
    pattern = meta.rsplit(":", 1)[-1]
    if pattern.startswith("!"):            # matched a negation: not ignored
        return False, source
    return True, source


def source_travels(source: str | None) -> bool:
    """True if the ignore rule lives in a `.gitignore` committed in the repo."""
    if not source:
        return False
    return (
        not os.path.isabs(source)
        and not source.startswith(".git/")
        and os.path.basename(source) == ".gitignore"
    )
