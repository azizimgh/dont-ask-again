"""Test corpus shared by the unit tests and bench/run_bench.py.

Every secret here is FAKE. Known-format tokens are assembled at runtime with
S() so this repo itself never matches GitHub push protection or other scanners.
"""


def S(*parts: str) -> str:
    return "".join(parts)


FAKE_GH = S("gh", "p_", "Zq7Lm2Xw9Rt4" * 3)
FAKE_ANT = S("sk-", "ant-", "api03-", "FakeKeyForTests" * 2)
FAKE_AKIA = S("AK", "IA", "Q3FAKEFAKEFAKE7Z")
FAKE_VAULT = S("hv", "s.", "CAESIFakeVaultTokenForTests123")

# (permission rule as Claude Code saves it, expected rule id)
POSITIVE = [
    ('Bash(PGPASSWORD=Tr0ub4dor-77 psql -h db.internal -U app -c "select 1")', "env-secret-literal"),
    ("Bash(MYSQL_PWD=s3cr3t-pw mysql -u root)", "env-secret-literal"),
    ("Bash(export DB_PASSWORD=pa55-w0rd-x && ./migrate.sh)", "env-secret-literal"),
    ('Bash(PGPASSWORD="Quoted Pass 1" psql -h db)', "env-secret-literal"),
    ("Bash(cd app;MYSQL_PWD=Semi-Pw-3 mysql)", "env-secret-literal"),
    ("Bash(bash -c 'PGPASSWORD=Nested-Pw-42 pg_dump app > /tmp/a.sql')", "env-secret-literal"),
    ("Bash(vault login -method=userpass username=ops password=V4ult-Pw-7)", "env-secret-literal"),
    ("Bash(kubectl create secret generic db --from-literal=password=Lit3ral-Pw)", "env-secret-literal"),
    ('Bash(sshpass -p "N0tMyRealPw!" ssh deploy@10.0.0.5)', "sshpass-password"),
    ("Bash(sshpass -pN0tMyRealPw ssh root@host)", "sshpass-password"),
    ("Bash(mysql -u root -pHunter2xyz -h 127.0.0.1 shop)", "mysql-password"),
    ("Bash(mysqldump --password=Dump-Pass-9 shop:*)", "mysql-password"),
    ("Bash(docker exec -it db mysql -uroot -pR00tPass55)", "mysql-password"),
    ("Bash(redis-cli -h cache -a Red1sPass99 ping)", "redis-cli-password"),
    ("Bash(docker login -u bot -p Regi5try-Pw registry.example.com)", "registry-login-password"),
    ("Bash(helm registry login ghcr.io --username bot --password Helm-Pw-123)", "registry-login-password"),
    ("Bash(curl -u admin:Adm1n-Pass https://jenkins.local/api/json)", "curl-user-password"),
    ("Bash(kubectl --token=eyJhbGciOiJSUzI1NiJ9.fake.sig get pods)", "generic-secret-flag"),
    ('Bash(curl -H "Authorization: Bearer abcd1234efgh5678ijkl" https://api.example.com/v1/me)', "header-authorization"),
    ('Bash(curl https://api.example.com -H "X-API-Key: k3y-12345-abcde")', "header-api-key"),
    ("Bash(psql postgres://app:Pg-Url-Pass-1@db.internal:5432/app)", "url-credentials"),
    ('Bash(mongosh "mongodb+srv://admin:M0ngo-Pass@cluster0.example.net/test")', "url-credentials"),
    ('Bash(curl "https://api.example.com/v1/data?api_key=QueryKey12345")', "url-query-secret"),
    (f"Bash(git clone https://x-access-token:{FAKE_GH}@github.com/org/repo.git)", "github-token"),
    (f"Bash(GITHUB_TOKEN={FAKE_GH} gh pr list)", "github-token"),
    (f"Bash(vault login {FAKE_VAULT})", "vault-token"),
    (f"Bash(ANTHROPIC_API_KEY={FAKE_ANT} python run.py)", "anthropic-api-key"),
    (f"Bash(AWS_ACCESS_KEY_ID={FAKE_AKIA} aws s3 ls)", "aws-access-key-id"),
    ("Bash(AWS_SECRET_ACCESS_KEY=wJalrFakeSecretKeyForTestsOnly1234567890 aws s3 ls)", "env-secret-literal"),
]

# Rules that must NOT be flagged.
NEGATIVE = [
    'Bash(PGPASSWORD="$PGPASSWORD" psql -h db)',
    "Bash(PGPASSWORD=${DB_PASS} psql)",
    "Bash(PGPASSWORD=* psql:*)",
    "Bash(mysql -u root -p shop)",
    "Bash(docker run -p 8080:80 nginx)",
    "Bash(docker login -u bot --password-stdin ghcr.io)",
    "Bash(npm run:*)",
    "Bash(npm run test:*)",
    'Bash(curl -H "Authorization: Bearer $TOKEN" https://api.example.com)',
    "Bash(curl -u admin https://jenkins.local)",
    "Bash(psql postgres://app@db/app)",
    "Bash(curl https://user:<password>@host/x)",
    "Bash(export NODE_AUTH_TOKEN=$(cat ~/.npmrc-token))",
    "Bash(ssh -i ~/.ssh/id_ed25519 deploy@host)",
    "Bash(SSH_PRIVATE_KEY=~/.ssh/id_rsa ./deploy.sh)",
    "Bash(CLAUDE_CODE_MAX_OUTPUT_TOKENS=64000 claude)",
    "Bash(MAX_TOKEN=4096 python x.py)",
    "Bash(DISABLE_AUTH=true npm start)",
    "Bash(docker build --secret id=npm,src=$HOME/.npmrc .)",
    "Bash(kubectl create secret generic db --from-literal=password=$DB_PASS)",
    "Bash(git push origin main)",
    "Read(./secrets/**)",
    "WebFetch(domain:github.com)",
    "Bash(vault login -method=oidc)",
]
