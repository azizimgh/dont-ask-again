# dont-ask-again

**Find the passwords your AI coding agent saved into your repo.**

When you click **"Yes, and don't ask again"** in Claude Code, it saves the exact command
as a permission rule in `.claude/settings.local.json`. If you typed a password into that
command, the password is saved too, in plain text:

```json
{
  "permissions": {
    "allow": [
      "Bash(PGPASSWORD=Tr0ub4dor-77 psql -h db.internal -U app)",
      "Bash(sshpass -p 'N0tMyRealPw!' ssh deploy@10.0.0.5)"
    ]
  }
}
```

Claude Code ignores that file only through your **global** git excludes, which exist on
your machine alone. A fresh clone, a CI job, `git add -f`, an npm package or a Docker
image doesn't see that rule.

In November 2026, [Apiiro's research](https://labs.cloudsecurityalliance.org/research/csa-research-note-claude-code-settings-secret-leak-20261108/)
found **2,539 secrets in 1,994 public repos** from these files. **gitleaks and TruffleHog
both missed 215 of the 1,122 leaking files**, mostly because a password after `sshpass -p`
or in `PGPASSWORD=` doesn't have a recognisable token format.

`dont-ask-again` reads the command the way a shell does, so it knows that the word after
`sshpass -p` is a password, whatever it looks like.

## Quick start

```bash
pipx run dont-ask-again scan            # or: uvx dont-ask-again scan
```

Python 3.11+, no dependencies.

```
ERROR DAA001 local-settings-tracked  .claude/settings.local.json
      Personal Claude Code settings are committed. ...

ERROR DAA002 env-secret-literal  .claude/settings.local.json:4
      permissions.allow[0]: Bash(PGPASSWORD=Tr****** psql -h db.internal -U app)
      Literal value for PGPASSWORD. Write PGPASSWORD="$PGPASSWORD" instead, so the
      approval stores the variable name, not the secret
```

Secrets are always masked in the output. The full value is never printed.

## What it checks

| Check | What | Severity |
|---|---|---|
| **DAA001** | `.claude/settings.local.json` is tracked by git (or, with `--history`, ever was) | error |
| **DAA002** | A literal secret in a permission rule, an `env` block, MCP `headers` or `args` | error (warn if the file is local-only) |
| **DAA003** | The file is ignored only by your global excludes, not the repo's `.gitignore`; or `.dockerignore` doesn't exclude `.claude/` | warn |
| **DAA004** | `npm pack` would publish `.claude/` | error |

Files scanned: `.claude/settings.local.json`, `.claude/settings.json`, `.mcp.json`,
`.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.windsurf/mcp.json`,
`.codex/config.toml`, at any depth.

What DAA002 catches (`dont-ask-again rules` lists them all):

- **Env assignments:** `PGPASSWORD=…`, `MYSQL_PWD=…`, `export DB_PASSWORD=…`, `*_TOKEN=…`, `*_API_KEY=…`, `kubectl --from-literal=password=…`, libpq `"host=… password=…"`
- **Password flags:** `sshpass -p`, `mysql -pX` / `--password=`, `mongosh -p`, `sqlcmd -P`, `redis-cli -a`, `ldapsearch -w`, `smbclient -U user%pass`, `openssl -passin pass:…`, `htpasswd -b`, `rabbitmqctl add_user`, `docker|podman|helm|az login -p`, `curl -u user:pass` / `--oauth2-bearer`, `vault login <token>`, `doctl auth init -t`, `--token`, `--api-key`, `--http-password`
- **Inside wrappers:** `bash -c '…'`, `docker exec db mysql -p…`, commands chained with `&&`, `;` and `|`
- **Headers:** `Authorization: Bearer …`, `X-API-Key: …`
- **URLs:** `postgres://user:pass@host`, `?api_key=…`
- **Config keys named like secrets:** `"api_key": "…"`, `bearer_token = "…"`, MCP `env`, `headers` and Codex `http_headers`
- **Known formats:** GitHub, GitLab, npm (incl. `_authToken`), AWS, Slack, Stripe, Google, Anthropic, OpenAI, Vault tokens and private keys

It skips references, which are the safe way to write these commands:
`PGPASSWORD="$PGPASSWORD"`, `${TOKEN}`, `$(cat file)`, `<password>`, and wildcards like `PGPASSWORD=*`.

## Options

```bash
dont-ask-again scan --history           # every version ever committed, not just the current files
dont-ask-again scan --format sarif -o daa.sarif
dont-ask-again scan --sarif daa.sarif     # text on screen and SARIF to a file, in one run
dont-ask-again scan --fail-on warn      # exit 1 on warnings too (default: errors only)
dont-ask-again scan --skip DAA004       # skip checks
dont-ask-again scan --skip DAA001,DAA003,DAA004   # file contents only, no git checks
```

Exit codes: `0` clean, `1` findings, `2` usage error.

To accept a finding, add its `fingerprint` to `.daaignore`. Fingerprints never encode the secret.

## Fixing it

**Rotate the credential first.** Deleting the file or rewriting history does not undo a
leak, because clones and forks keep their copies.

```bash
dont-ask-again fix                      # dry run: shows what it would do
dont-ask-again fix --redact-local --yes # apply
```

`fix` will:
- `git rm --cached` a tracked `settings.local.json`. Your local copy stays.
- Add `**/.claude/settings.local.json` to the repo's `.gitignore`, and `**/.claude` to `.dockerignore`.
- With `--redact-local`: remove the permission rules that hold a secret. Claude Code will
  ask again next time. A backup goes to `~/.dont-ask-again/backups/` (mode 600), outside
  the repo so it can't be committed by accident.

It never rewrites git history. It tells you how, if you decide to.

**Going forward**, approve commands that refer to the secret, not ones that contain it:
`PGPASSWORD="$PGPASSWORD" psql …`. The saved rule then holds the variable name only.

## pre-commit

```yaml
repos:
  - repo: https://github.com/azizimgh/dont-ask-again
    rev: v0.1.0
    hooks:
      - id: dont-ask-again
```

A local-only secret (untracked and ignored) is a warning, so it won't block your commits.
Anything that git would actually commit is an error.

## GitHub Action

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0            # only needed for history: true
- uses: azizimgh/dont-ask-again@v0.1.0
  with:
    history: "true"
    sarif: "true"             # needs `permissions: security-events: write`
```

## How it compares

`dont-ask-again` **complements** gitleaks and TruffleHog; it doesn't replace them. They
scan everything for known token formats. This scans a handful of agent config files and
understands the commands inside them. Run both.

To see what each tool catches on the fake test corpus:

```bash
python bench/run_bench.py
```

Not covered here (other tools already do it well): secrets in local agent **chat
transcripts** (`~/.claude/projects/*.jsonl`). See agent-transcript-secrets, agentleaks or cc-scrub.

## Contributing

Each new pattern is **one entry in [`rules.toml`](src/dont_ask_again/rules.toml) plus one
line in [`tests/cases.py`](tests/cases.py)**. See [CONTRIBUTING.md](CONTRIBUTING.md).
**Never paste a real secret in an issue**: see [SECURITY.md](SECURITY.md).

## License

MIT
