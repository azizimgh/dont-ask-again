"""Test corpus shared by the unit tests and bench/run_bench.py.

Every secret here is FAKE. Token-style values are random but seeded, so runs are
repeatable and they look like real tokens (high entropy). That keeps the
benchmark fair: gitleaks and TruffleHog rightly ignore low-entropy strings such
as "FakeKeyForTests". They are assembled at runtime, so this repo itself never
contains a token-shaped string for push protection or other scanners to match.
Human-style passwords (e.g. Tr0ub4dor-77) stay readable, because real ones look like that.
"""

import random
import string

_RNG = random.Random(20261125)
_ALNUM = string.ascii_letters + string.digits


def S(*parts: str) -> str:
    return "".join(parts)


def R(n: int, alphabet: str = _ALNUM) -> str:
    """Seeded random characters: a fake that looks like a real token."""
    return "".join(_RNG.choice(alphabet) for _ in range(n))


FAKE_GH = S("gh", "p_", R(36))
FAKE_ANT = S("sk-", "ant-", "api03-", R(93, _ALNUM + "-_"), "AA")
FAKE_AKIA = S("AK", "IA", R(16, string.ascii_uppercase + "234567"))
FAKE_AWS_SECRET = R(40, _ALNUM + "+/")
FAKE_VAULT = S("hv", "s.", R(90, _ALNUM + "_-"))
FAKE_BEARER = R(40, _ALNUM)
FAKE_API_KEY = R(32, string.hexdigits.lower()[:16])

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
    (f'Bash(curl -H "Authorization: Bearer {FAKE_BEARER}" https://api.example.com/v1/me)', "header-authorization"),
    (f'Bash(curl https://api.example.com -H "X-API-Key: {FAKE_API_KEY}")', "header-api-key"),
    ("Bash(psql postgres://app:Pg-Url-Pass-1@db.internal:5432/app)", "url-credentials"),
    ('Bash(mongosh "mongodb+srv://admin:M0ngo-Pass@cluster0.example.net/test")', "url-credentials"),
    (f'Bash(curl "https://api.example.com/v1/data?api_key={FAKE_API_KEY}")', "url-query-secret"),
    (f"Bash(git clone https://x-access-token:{FAKE_GH}@github.com/org/repo.git)", "github-token"),
    (f"Bash(GITHUB_TOKEN={FAKE_GH} gh pr list)", "github-token"),
    (f"Bash(vault login {FAKE_VAULT})", "vault-token"),
    (f"Bash(ANTHROPIC_API_KEY={FAKE_ANT} python run.py)", "anthropic-api-key"),
    (f"Bash(AWS_ACCESS_KEY_ID={FAKE_AKIA} aws s3 ls)", "aws-access-key-id"),
    (f"Bash(AWS_SECRET_ACCESS_KEY={FAKE_AWS_SECRET} aws s3 ls)", "env-secret-literal"),
    # v0.2 patterns
    ("Bash(mongosh -u admin -p M0ngoCli-Pw mongodb://db.internal/app)", "mongo-password"),
    ("Bash(sqlcmd -S db.internal -U sa -P Sql-Pass-9 -Q 'select 1')", "sqlcmd-password"),
    ("Bash(ldapsearch -x -D cn=admin,dc=example,dc=org -w Ldap-Pass-1 -b dc=example,dc=org)", "ldap-password"),
    ("Bash(smbclient //files/share -U bob%Smb-Pass-2)", "smbclient-password"),
    ("Bash(openssl pkcs12 -in cert.p12 -nodes -passin pass:P12-Pass-3)", "openssl-pass"),
    ("Bash(az login -u ops@example.com -p Azure-Pass-4)", "az-login-password"),
    (f"Bash(doctl auth init -t dop_v1_{R(64, '0123456789abcdef')})", "doctl-token"),
    (f"Bash(curl --oauth2-bearer {FAKE_BEARER} https://api.example.com)", "curl-oauth2-bearer"),
    ("Bash(htpasswd -bc .htpasswd admin Htpw-Pass-5)", "htpasswd-batch-password"),
    ("Bash(rabbitmqctl add_user app Rabbit-Pass-6)", "rabbitmqctl-password"),
    (f"Bash(npm config set //registry.npmjs.org/:_authToken {R(36)})", "npm-auth-token"),
    ('Bash(psql "host=db.internal user=app password=Libpq-Pass-7 dbname=app")', "env-secret-literal"),
    ("Bash(wget --http-password=Wget-Pass-8 https://files.example.com/a.tgz)", "generic-secret-flag"),
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
    # v0.2 safe forms
    "Bash(mongosh --host db.internal -u admin)",
    "Bash(sqlcmd -S db.internal -E)",
    "Bash(ldapsearch -x -W -D cn=admin,dc=example,dc=org)",
    "Bash(smbclient //files/share -U bob)",
    "Bash(openssl rsa -in key.pem -passin env:KEY_PASS)",
    "Bash(openssl rsa -in key.pem -passin file:./pw.txt)",
    "Bash(az login --identity)",
    "Bash(curl --oauth2-bearer $TOKEN https://api.example.com)",
    "Bash(htpasswd -c .htpasswd admin)",
    "Bash(rabbitmqctl add_user app)",
    "Bash(npm config set //registry.npmjs.org/:_authToken ${NPM_TOKEN})",
]
