"""Compare dont-ask-again with gitleaks and TruffleHog on the fake test corpus.

    python bench/run_bench.py            # markdown table to stdout

Each positive case is written to its own `.claude/settings.local.json` in a temp
dir, and each tool is asked whether it finds anything there. Tools that aren't
installed are reported as "not installed". Every secret in the corpus is fake.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from cases import NEGATIVE, POSITIVE  # noqa: E402

from dont_ask_again.models import GIT_CHECKS  # noqa: E402
from dont_ask_again.scanner import scan  # noqa: E402


def write_case(base: Path, i: int, rule: str) -> Path:
    d = base / f"case-{i:02d}"
    (d / ".claude").mkdir(parents=True)
    (d / ".claude" / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": [rule], "deny": []}}, indent=2) + "\n"
    )
    return d


def ours(d: Path) -> bool:
    return any(f.check == "DAA002" for f in scan(d, skip=GIT_CHECKS).findings)


def gitleaks(d: Path) -> bool | None:
    exe = shutil.which("gitleaks")
    if not exe:
        return None
    report = d / "gitleaks.json"
    cmd = [exe, "dir", str(d / ".claude"), "--no-banner", "--report-format", "json", "--report-path", str(report)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if "unknown command" in p.stderr:  # gitleaks < 8.19
        cmd = [exe, "detect", "--no-git", "--source", str(d / ".claude"), "--no-banner", "--report-format", "json", "--report-path", str(report)]
        subprocess.run(cmd, capture_output=True, text=True)
    try:
        return bool(json.loads(report.read_text() or "[]"))
    except (OSError, json.JSONDecodeError):
        return False


def trufflehog(d: Path) -> bool | None:
    exe = shutil.which("trufflehog")
    if not exe:
        return None
    p = subprocess.run([exe, "filesystem", str(d / ".claude"), "--json", "--no-verification", "--no-update"], capture_output=True, text=True)
    return any(line.strip().startswith("{") and '"SourceMetadata"' in line for line in p.stdout.splitlines())


def cell(v: bool | None) -> str:
    return "n/a" if v is None else ("✅" if v else "❌")


def main() -> int:
    tools = {"dont-ask-again": ours, "gitleaks": gitleaks, "trufflehog": trufflehog}
    totals = {t: 0 for t in tools}
    installed = {t: True for t in tools}
    rows = []
    with tempfile.TemporaryDirectory(prefix="daa-bench-") as tmp:
        base = Path(tmp)
        for i, (rule, expected) in enumerate(POSITIVE):
            d = write_case(base, i, rule)
            res = {t: fn(d) for t, fn in tools.items()}
            for t, v in res.items():
                if v is None:
                    installed[t] = False
                elif v:
                    totals[t] += 1
            rows.append((expected, res))

        fp = sum(ours(write_case(base, 100 + i, r)) for i, r in enumerate(NEGATIVE))

    print("| case (expected rule) | " + " | ".join(tools) + " |")
    print("|---|" + "---|" * len(tools))
    for expected, res in rows:
        print(f"| {expected} | " + " | ".join(cell(res[t]) for t in tools) + " |")
    n = len(POSITIVE)
    print("| **caught** | " + " | ".join(f"**{totals[t]}/{n}**" if installed[t] else "not installed" for t in tools) + " |")
    print(f"\ndont-ask-again false positives on {len(NEGATIVE)} safe rules: {fp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
