"""Text, JSON and SARIF output. Secrets are always masked."""

from __future__ import annotations

import json

from . import __version__
from .models import CHECKS, ScanResult

INFO_URI = "https://github.com/azizimgh/dont-ask-again"


def text(result: ScanResult) -> str:
    lines = [f"dont-ask-again {__version__}: scanned {len(result.files)} agent config file(s) in {result.root}"]
    if not result.findings:
        lines.append("No findings.")
    for f in result.findings:
        where = f.file + (f":{f.line}" if f.line else "")
        if f.commit:
            where += f" @ {f.commit}"
        lines.append("")
        lines.append(f"{f.severity.upper():5} {f.check} {f.rule}  {where}")
        if f.snippet:
            prefix = f"{f.location}: " if f.location else ""
            lines.append(f"      {prefix}{f.snippet}")
        lines.append(f"      {f.message}")
        lines.append(f"      fingerprint: {f.fingerprint}")
    for n in result.notes:
        lines.append(f"\nnote: {n}")
    if result.findings:
        lines.append("")
        lines.append(f"{len(result.errors)} error(s), {len(result.warnings)} warning(s).")
        if any(f.check == "DAA002" for f in result.findings):
            lines.append(
                "Rotate every exposed credential first. Deleting the file or rewriting history "
                "does not undo a leak. Then run `dont-ask-again fix`."
            )
    return "\n".join(lines)


def as_json(result: ScanResult) -> str:
    return json.dumps(
        {
            "tool": "dont-ask-again",
            "version": __version__,
            "root": str(result.root),
            "files_scanned": result.files,
            "errors": len(result.errors),
            "warnings": len(result.warnings),
            "findings": [f.to_dict() for f in result.findings],
            "notes": result.notes,
        },
        indent=2,
    )


def sarif(result: ScanResult) -> str:
    rules = [
        {
            "id": cid,
            "name": cid,
            "shortDescription": {"text": desc},
            "helpUri": f"{INFO_URI}#{cid.lower()}",
        }
        for cid, desc in CHECKS.items()
    ]
    results = []
    for f in result.findings:
        loc: dict = {"artifactLocation": {"uri": f.file}}
        if f.line:
            loc["region"] = {"startLine": f.line}
        msg = f.message if not f.snippet else f"{f.message}\n{f.snippet}"
        results.append(
            {
                "ruleId": f.check,
                "level": "error" if f.severity == "error" else "warning",
                "message": {"text": msg},
                "locations": [{"physicalLocation": loc}],
                "partialFingerprints": {"daa/v1": f.fingerprint},
                "properties": {"rule": f.rule, **({"commit": f.commit} if f.commit else {})},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dont-ask-again",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(doc, indent=2)
