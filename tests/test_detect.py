import json
import unittest

from cases import FAKE_GH, NEGATIVE, POSITIVE

from dont_ask_again.detect import Detector, mask
from dont_ask_again.rules import load_rules
from dont_ask_again.scanner import scan_json_text, unwrap_rule

DET = Detector(load_rules())


def settings(*rules: str) -> str:
    return json.dumps({"permissions": {"allow": list(rules), "deny": []}}, indent=2)


class TestPositive(unittest.TestCase):
    def test_each_case(self):
        for rule, expected in POSITIVE:
            with self.subTest(rule=rule):
                findings = scan_json_text(settings(rule), ".claude/settings.local.json", DET)
                self.assertIn(expected, {f.rule for f in findings}, f"missed: {rule}")

    def test_line_numbers_point_at_the_rule(self):
        text = settings("Bash(ls)", "Bash(MYSQL_PWD=s3cr3t-pw mysql -u root)")
        [f] = scan_json_text(text, "x/.claude/settings.json", DET)
        self.assertIn("MYSQL_PWD", text.splitlines()[f.line - 1])

    def test_snippet_never_contains_the_secret(self):
        for rule, _ in POSITIVE:
            for f in scan_json_text(settings(rule), ".claude/settings.local.json", DET):
                with self.subTest(rule=rule):
                    secret = f.raw  # the raw rule; check that no long secret survives masking
                    self.assertNotIn("Tr0ub4dor-77", f.snippet)
                    self.assertNotIn(FAKE_GH, f.snippet)
                    self.assertNotIn(f.fingerprint, secret)

    def test_bash_c_reports_only_the_password(self):
        hits = DET.scan_command("bash -c 'PGPASSWORD=Nested-Pw-42 pg_dump app'")
        self.assertEqual([h.secret for h in hits], ["Nested-Pw-42"])


class TestNegative(unittest.TestCase):
    def test_each_case(self):
        for rule in NEGATIVE:
            with self.subTest(rule=rule):
                findings = scan_json_text(settings(rule), ".claude/settings.local.json", DET)
                self.assertEqual([], [(f.rule, f.snippet) for f in findings])


class TestMcpConfig(unittest.TestCase):
    def test_env_headers_and_args(self):
        cfg = {
            "mcpServers": {
                "gh": {"command": "npx", "args": ["-y", "server-github"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": FAKE_GH}},
                "api": {"type": "http", "url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer mcp-hdr-token-123456"}},
                "db": {"command": "uvx", "args": ["mcp-postgres", "--password", "Arg-Pass-77"]},
                "safe": {"command": "node", "args": ["server.js"], "env": {"API_KEY": "${API_KEY}"}},
            }
        }
        findings = scan_json_text(json.dumps(cfg, indent=2), ".mcp.json", DET)
        self.assertEqual(
            sorted(f.rule for f in findings),
            ["generic-secret-flag", "github-token", "header-authorization"],
        )

    def test_invalid_json_is_skipped(self):
        self.assertEqual(scan_json_text("{not json", ".mcp.json", DET), [])


class TestHelpers(unittest.TestCase):
    def test_unwrap(self):
        self.assertEqual(unwrap_rule("Bash(npm run test:*)"), "npm run test")
        self.assertEqual(unwrap_rule("Bash(ls -la)"), "ls -la")
        self.assertEqual(unwrap_rule("plain"), "plain")

    def test_mask(self):
        self.assertEqual(mask("abc"), "******")
        self.assertEqual(mask("Hunter2xyz"), "Hu******")
        self.assertTrue(mask(FAKE_GH).startswith("ghp_"))
        self.assertNotIn(FAKE_GH[4:], mask(FAKE_GH))


if __name__ == "__main__":
    unittest.main()
