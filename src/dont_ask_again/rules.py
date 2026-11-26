"""Load the TOML rule pack."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

# How a flag carries its value. See the notation at the top of rules.toml.
NEXT_OR_ATTACHED = "next-or-attached"  # "-p"          -p VALUE / -pVALUE
ATTACHED = "attached"                  # "-p..."       -pVALUE
NEXT_OR_EQ = "next-or-eq"              # "--password"  --password VALUE / --password=VALUE
EQ = "eq"                              # "--password=" --password=VALUE


def parse_flag(spec: str) -> tuple[str, str]:
    for suffix in ("...", "…"):
        if spec.endswith(suffix):
            return spec[: -len(suffix)], ATTACHED
    if spec.endswith("="):
        return spec[:-1], EQ
    return spec, NEXT_OR_EQ if spec.startswith("--") else NEXT_OR_ATTACHED


@dataclass(frozen=True)
class EnvRule:
    id: str
    description: str
    name: re.Pattern[str]


@dataclass(frozen=True)
class FlagRule:
    id: str
    description: str
    programs: tuple[str, ...]
    flags: tuple[tuple[str, str], ...] = ()  # (flag, how) from parse_flag
    requires: tuple[str, ...] = ()           # a word that must follow the program first (e.g. "login")
    exclude_programs: tuple[str, ...] = ()
    positional: int = 0                      # take the Nth plain argument (after `requires`); 0 = off
    value: re.Pattern[str] | None = None


@dataclass(frozen=True)
class RegexRule:
    id: str
    description: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class RulePack:
    env: tuple[EnvRule, ...]
    flags: tuple[FlagRule, ...]
    regexes: tuple[RegexRule, ...]
    placeholders: tuple[re.Pattern[str], ...]

    def all_ids(self) -> list[tuple[str, str, str]]:
        """(kind, id, description) for every rule."""
        return (
            [("regex", r.id, r.description) for r in self.regexes]
            + [("flag", r.id, r.description) for r in self.flags]
            + [("env", r.id, r.description) for r in self.env]
        )


def load_rules(path: str | Path | None = None) -> RulePack:
    if path is None:
        text = resources.files("dont_ask_again").joinpath("rules.toml").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    data = tomllib.loads(text)

    return RulePack(
        env=tuple(EnvRule(e["id"], e["description"], re.compile(e["name"])) for e in data.get("env", [])),
        flags=tuple(
            FlagRule(
                id=f["id"],
                description=f["description"],
                programs=tuple(f["programs"]),
                flags=tuple(parse_flag(s) for s in f.get("flags", ())),
                requires=tuple(f.get("requires", ())),
                exclude_programs=tuple(f.get("exclude_programs", ())),
                positional=int(f.get("positional", 0)),  # `true` counts as 1
                value=re.compile(f["value"]) if "value" in f else None,
            )
            for f in data.get("flag", [])
        ),
        regexes=tuple(RegexRule(r["id"], r["description"], re.compile(r["regex"])) for r in data.get("regex", [])),
        placeholders=tuple(re.compile(p, re.IGNORECASE) for p in data.get("placeholders", {}).get("regex", [])),
    )
