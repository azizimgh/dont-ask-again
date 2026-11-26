"""Find secrets inside shell commands and config values.

This is where we beat format-based scanners: instead of only matching known
token shapes, we split the command into words and look at *where* a value
sits (after `sshpass -p`, in `PGPASSWORD=...`, after `mysql -p`, ...).
"""

from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass

from .rules import ATTACHED, EQ, NEXT_OR_ATTACHED, NEXT_OR_EQ, FlagRule, RulePack

ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.S)
OPTION_PREFIX_RE = re.compile(r"^--?[A-Za-z][\w-]*=")  # --env=NAME=VALUE, --from-literal=k=v
PATH_LIKE_RE = re.compile(r"^(/|\./|\.\./|~/)|^[\w.-]+\.(pem|key|json|txt|crt|p12|pfx|env)$")
SEPARATORS = set("();<>|&")
SHELL_SCRIPT_FLAGS = {"-c", "-lc", "-ic", "-ec", "-xc", "-euc", "-exc"}
MAX_DEPTH = 2  # how deep to look into `bash -c '...'`


@dataclass(frozen=True)
class Hit:
    rule_id: str
    secret: str
    message: str


def tokenize(cmd: str) -> list[str]:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    lex.commenters = ""  # a '#' inside a password must not start a comment
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: fall back to plain splitting
        return cmd.split()


def segments(tokens: list[str]):
    """Split a token list into simple commands at ; && || | ( ) etc."""
    seg: list[str] = []
    for t in tokens:
        if t and all(c in SEPARATORS for c in t):
            if seg:
                yield seg
            seg = []
        else:
            seg.append(t)
    if seg:
        yield seg


def dedupe(hits: list[Hit]) -> list[Hit]:
    seen: set[str] = set()
    out = []
    for h in hits:
        if h.secret in seen:
            continue
        seen.add(h.secret)
        out.append(h)
    return out


class Detector:
    def __init__(self, rules: RulePack):
        self.rules = rules

    # -- helpers -------------------------------------------------------------

    def is_placeholder(self, value: str) -> bool:
        v = value.strip().strip("\"'")
        if len(v) < 3:
            return True
        return any(p.search(v) for p in self.rules.placeholders)

    # -- public API ----------------------------------------------------------

    def scan_text(self, s: str) -> list[Hit]:
        """Known token formats, auth headers and URL credentials anywhere in a string."""
        hits = []
        for r in self.rules.regexes:
            for m in r.regex.finditer(s):
                secret = m.groupdict().get("secret") or m.group(0)
                if not self.is_placeholder(secret):
                    hits.append(Hit(r.id, secret, r.description))
        return dedupe(hits)

    def env_value(self, name: str, value: str, in_command: bool = True) -> Hit | None:
        """A NAME=value pair, from a command or from a JSON "env" block."""
        for r in self.rules.env:
            if r.name.match(name) and not self.is_placeholder(value) and not PATH_LIKE_RE.search(value):
                if in_command:
                    advice = (
                        f'Literal value for {name}. Write {name}="${name}" instead, '
                        "so the approval stores the variable name, not the secret"
                    )
                else:
                    advice = (
                        f"Literal value for {name} in a config file. Keep this file out of git, "
                        f'or reference it ("${{{name}}}" in MCP configs) and set it in your shell or secret manager'
                    )
                return Hit(r.id, value, advice)
        return None

    def scan_command(self, cmd: str, depth: int = 0) -> list[Hit]:
        hits = self.scan_text(cmd)
        tokens = tokenize(cmd)
        for seg in segments(tokens):
            hits += self._flag_hits(seg)
            for k, t in enumerate(seg):
                if k > 0 and seg[k - 1] in SHELL_SCRIPT_FLAGS:
                    # `bash -c '...'`: the argument is a script, look inside it instead
                    if depth < MAX_DEPTH:
                        hits += self.scan_command(t, depth + 1)
                    continue
                candidates = [t]
                if OPTION_PREFIX_RE.match(t):
                    candidates.append(OPTION_PREFIX_RE.sub("", t, count=1))
                for c in candidates:
                    m = ASSIGN_RE.match(c)
                    if m:
                        h = self.env_value(m.group(1), m.group(2))
                        if h:
                            hits.append(h)
                if depth < MAX_DEPTH and any(ch.isspace() for ch in t.strip()):
                    hits += self.scan_command(t, depth + 1)  # bash -c '...', sh -c "..."
        return dedupe(hits)

    # -- flags ---------------------------------------------------------------

    def _flag_hits(self, seg: list[str]) -> list[Hit]:
        hits = []
        names = [os.path.basename(t) for t in seg]
        for r in self.rules.flags:
            if r.programs == ("*",):
                if any(n in r.exclude_programs for n in names):
                    continue
                starts = [-1]
            else:
                starts = [i for i, n in enumerate(names) if n in r.programs]
            for i in starts:
                rest = seg[i + 1 :]
                if r.requires:
                    idx = next((k for k, t in enumerate(rest) if t in r.requires), None)
                    if idx is None:
                        continue
                    rest = rest[idx + 1 :]
                for cand in _flag_values(r, rest):
                    secret = cand
                    if r.value is not None:
                        m = r.value.match(cand)
                        if not m:
                            continue
                        secret = m.groupdict().get("secret") or m.group(0)
                    if not self.is_placeholder(secret):
                        hits.append(Hit(r.id, secret, r.description))
        return hits


def _flag_values(r: FlagRule, rest: list[str]) -> list[str]:
    if r.positional:
        plain = [t for t in rest if not t.startswith("-") and "=" not in t]
        return plain[r.positional - 1 : r.positional]

    out = []
    for k, t in enumerate(rest):
        nxt = rest[k + 1] if k + 1 < len(rest) else None
        for flag, how in r.flags:
            if how in (NEXT_OR_ATTACHED, NEXT_OR_EQ) and t == flag and nxt is not None:
                out.append(nxt)
            elif how in (NEXT_OR_ATTACHED, ATTACHED) and not t.startswith("--") and t.startswith(flag) and len(t) > len(flag):
                out.append(t[len(flag) :])
            elif how in (NEXT_OR_EQ, EQ) and t.startswith(flag + "="):
                out.append(t[len(flag) + 1 :])
    return out


def mask(secret: str) -> str:
    """Show just enough to recognise a secret, never enough to use it."""
    if len(secret) <= 6:
        return "******"
    if len(secret) < 16:
        return secret[:2] + "******"
    return secret[:4] + "********"
