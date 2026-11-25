"""Load the TOML rule pack."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path


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
    short: tuple[str, ...] = ()       # -p VALUE  or  -pVALUE
    attached: tuple[str, ...] = ()    # only -pVALUE
    long: tuple[str, ...] = ()        # --password VALUE  or  --password=VALUE
    long_eq: tuple[str, ...] = ()     # only --password=VALUE
    requires: tuple[str, ...] = ()    # a token that must follow the program first (e.g. "login")
    exclude_programs: tuple[str, ...] = ()
    positional: bool = False          # first positional argument after `requires`
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
    headers: tuple[RegexRule, ...]
    urls: tuple[RegexRule, ...]
    patterns: tuple[RegexRule, ...]
    placeholders: tuple[re.Pattern[str], ...]

    def all_ids(self) -> list[tuple[str, str, str]]:
        """(kind, id, description) for every rule."""
        out: list[tuple[str, str, str]] = []
        for kind, group in (
            ("pattern", self.patterns),
            ("header", self.headers),
            ("url", self.urls),
            ("flag", self.flags),
            ("env", self.env),
        ):
            out.extend((kind, r.id, r.description) for r in group)
        return out


def _regex_rules(items: list[dict]) -> tuple[RegexRule, ...]:
    return tuple(RegexRule(i["id"], i["description"], re.compile(i["regex"])) for i in items)


def load_rules(path: str | Path | None = None) -> RulePack:
    if path is None:
        text = resources.files("dont_ask_again").joinpath("rules.toml").read_text(encoding="utf-8")
    else:
        text = Path(path).read_text(encoding="utf-8")
    data = tomllib.loads(text)

    flags = []
    for f in data.get("flag", []):
        flags.append(
            FlagRule(
                id=f["id"],
                description=f["description"],
                programs=tuple(f["programs"]),
                short=tuple(f.get("short", ())),
                attached=tuple(f.get("attached", ())),
                long=tuple(f.get("long", ())),
                long_eq=tuple(f.get("long_eq", ())),
                requires=tuple(f.get("requires", ())),
                exclude_programs=tuple(f.get("exclude_programs", ())),
                positional=bool(f.get("positional", False)),
                value=re.compile(f["value"]) if "value" in f else None,
            )
        )

    return RulePack(
        env=tuple(EnvRule(e["id"], e["description"], re.compile(e["name"])) for e in data.get("env", [])),
        flags=tuple(flags),
        headers=_regex_rules(data.get("header", [])),
        urls=_regex_rules(data.get("url", [])),
        patterns=_regex_rules(data.get("pattern", [])),
        placeholders=tuple(
            re.compile(p, re.IGNORECASE) for p in data.get("placeholders", {}).get("regex", [])
        ),
    )
