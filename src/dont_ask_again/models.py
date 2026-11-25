"""Data types shared by every module."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

CHECKS = {
    "DAA001": "Agent local settings file is tracked by git",
    "DAA002": "Literal secret saved in agent config",
    "DAA003": "Agent config is not ignored by the repo itself",
    "DAA004": "npm package would publish agent config",
}
GIT_CHECKS = {"DAA001", "DAA003", "DAA004"}
SEVERITY_ORDER = {"error": 0, "warn": 1}


def fingerprint(*parts: str) -> str:
    """Stable id for .daaignore. Callers must never pass the secret itself."""
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:12]


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
    raw: str = field(default="", repr=False)     # original value, never printed
    secret: str = field(default="", repr=False)  # only for de-duplication, never printed

    def __post_init__(self) -> None:
        if not self.fingerprint:
            self.fingerprint = fingerprint(self.check, self.rule, self.file)

    def to_dict(self) -> dict:
        d = asdict(self)
        del d["raw"], d["secret"]
        return d

    @property
    def dedupe_key(self) -> tuple[str, str, str]:
        # Uses the real secret: two different passwords are two findings, even if the
        # rule text around them is identical (e.g. a password rotated across commits).
        return (self.file, self.rule, self.secret or self.fingerprint)


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
