# Contributing

Thanks for helping. The most useful contributions are **new patterns** and **false-positive fixes**.

## Add a pattern (most common)

1. Add an entry to [`src/dont_ask_again/rules.toml`](src/dont_ask_again/rules.toml). The file explains each rule kind (`env`, `flag`, `header`, `url`, `pattern`).
2. Add the permission rule as Claude Code would save it to `POSITIVE` in [`tests/cases.py`](tests/cases.py), with the expected rule id.
3. If there is a safe form that must **not** be flagged (e.g. `$VAR`), add it to `NEGATIVE`.
4. Run the tests:

   ```bash
   PYTHONPATH=src:tests python -m unittest discover -s tests
   ```

**Only use fake secrets.** For known token formats (`ghp_…`, `AKIA…`), build the string with
`S("gh", "p_", ...)` so this repo never matches GitHub push protection.

Good first patterns to add: `mongosh -p`, `psql "password=…"` connection strings,
`htpasswd -b`, `az login -p`, `gcloud … --access-token-file` vs literal tokens, `.codex/config.toml`.

## Report a false positive

Open an issue with a **fake** version of the rule that was flagged (replace the value but keep its shape).

## Development

- Python 3.11+, standard library only. Please keep it dependency-free.
- `python -m dont_ask_again scan PATH` runs from a checkout (`PYTHONPATH=src`).
- `python bench/run_bench.py` compares with gitleaks/TruffleHog if they are installed.
