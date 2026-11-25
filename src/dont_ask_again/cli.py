"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, fix, report
from .models import ScanResult
from .rules import load_rules
from .scanner import scan

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
FORMATS = {"text": report.text, "json": report.as_json, "sarif": report.sarif}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dont-ask-again",
        description="Find secrets that AI coding agents saved into repo config "
        "(Claude Code 'don't ask again' approvals, MCP configs).",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("path", nargs="?", default=".", help="directory or file to scan (default: .)")
    common.add_argument("--history", action="store_true", help="also scan every committed version in git history")
    common.add_argument("--rules", metavar="FILE", help="use this rules.toml instead of the built-in one")
    common.add_argument("--skip", metavar="IDS", default="", help="comma-separated checks to skip, e.g. DAA004 or DAA001,DAA003,DAA004")

    s = sub.add_parser("scan", parents=[common], help="scan and report")
    s.add_argument("--format", choices=list(FORMATS), default="text")
    s.add_argument("--output", "-o", metavar="FILE", help="write the report to FILE instead of stdout")
    s.add_argument("--sarif", metavar="FILE", help="also write a SARIF report to FILE")
    s.add_argument("--fail-on", choices=["error", "warn", "never"], default="error", help="exit 1 when findings at this level exist (default: error)")

    f = sub.add_parser("fix", parents=[common], help="untrack, add ignores, optionally remove secret rules")
    f.add_argument("--redact-local", action="store_true", help="remove permission rules that hold a secret (backup kept outside the repo)")
    f.add_argument("--yes", "-y", action="store_true", help="apply the changes (default is a dry run)")

    sub.add_parser("rules", help="list the built-in rules")
    return p


def _run_scan(args) -> ScanResult:
    path = Path(args.path)
    if not path.exists():
        print(f"dont-ask-again: no such path: {path}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    skip = {x.strip() for x in args.skip.split(",") if x.strip()}
    return scan(path, rules=load_rules(args.rules), history=args.history, skip=skip)


def cmd_scan(args) -> int:
    result = _run_scan(args)
    out = FORMATS[args.format](result)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    if args.sarif:
        Path(args.sarif).write_text(report.sarif(result) + "\n", encoding="utf-8")
    if args.fail_on == "never":
        return EXIT_OK
    return EXIT_FINDINGS if result.errors or (args.fail_on == "warn" and result.warnings) else EXIT_OK


def cmd_fix(args) -> int:
    actions, manual = fix.plan(_run_scan(args), redact_local=args.redact_local)
    if not actions and not manual:
        print("Nothing to fix.")
        return EXIT_OK
    if actions:
        print("Will do:" if args.yes else "Would do (dry run, add --yes to apply):")
        for a in actions:
            print(f"  - {a.summary}")
    if args.yes and actions:
        for a in actions:
            if msg := a.apply():
                print(f"  {msg}")
        print("Done. Review with `git status` / `git diff`, then commit.")
    if manual:
        print("\nYou need to do:")
        for m in manual:
            print(f"  - {m}")
    return EXIT_OK


def cmd_rules(_args) -> int:
    for kind, rid, desc in load_rules().all_ids():
        print(f"{kind:6} {rid:26} {desc}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    return {"scan": cmd_scan, "fix": cmd_fix, "rules": cmd_rules}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
