# Review guide

What matters most when reviewing a change to dont-ask-again, in order:

1. **A secret must never be printed.** Every output path (text, JSON, SARIF, `fix` messages, exceptions)
   must show secrets only through `mask()`. A fingerprint must never be derived from the secret.
   `Finding.raw` and `Finding.secret` must stay out of `to_dict()` and every report.
2. **Missed secrets.** A rule change that stops catching a `POSITIVE` case in `tests/cases.py`, or a
   detection change without a new test case.
3. **False positives.** References like `$VAR`, `${VAR}`, `$(cmd)`, `<placeholder>` and `*` wildcards must
   not be flagged. A new rule needs a `NEGATIVE` case for its safe form.
4. **`fix` must be safe.** Dry run unless `--yes`. Never rewrite git history. Backups go outside the repo
   with mode 600.
5. **Fake secrets only** in tests and docs. Known-format tokens must be assembled at runtime with `S()`.
6. **No dependencies.** Python 3.11+ standard library only.

Not worth comments: formatting, line length, naming preferences.
