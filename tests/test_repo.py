"""End-to-end tests against throwaway git repos."""

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from dont_ask_again import cli, fix
from dont_ask_again.scanner import scan

SECRET_RULE = "Bash(PGPASSWORD=Tr0ub4dor-77 psql -h db -U app)"


def git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout


class RepoTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._home = Path(tempfile.mkdtemp(prefix="daa-home-"))
        # Mimic Claude Code: settings.local.json is ignored only via the *global* excludes file.
        (cls._home / "global-ignore").write_text("**/.claude/settings.local.json\n")
        (cls._home / "gitconfig").write_text(
            "[user]\n\tname = Test\n\temail = test@example.invalid\n"
            f"[core]\n\texcludesFile = {cls._home / 'global-ignore'}\n"
            "[init]\n\tdefaultBranch = main\n[commit]\n\tgpgsign = false\n"
        )
        cls._env = {k: os.environ.get(k) for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM")}
        os.environ["GIT_CONFIG_GLOBAL"] = str(cls._home / "gitconfig")
        os.environ["GIT_CONFIG_NOSYSTEM"] = "1"
        cls._backup_dir = fix.BACKUP_DIR
        fix.BACKUP_DIR = cls._home / "backups"

    @classmethod
    def tearDownClass(cls):
        for k, v in cls._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        fix.BACKUP_DIR = cls._backup_dir
        shutil.rmtree(cls._home, ignore_errors=True)

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(prefix="daa-repo-"))
        git(self.repo, "init", "-q")
        (self.repo / "README.md").write_text("hi\n")
        git(self.repo, "add", "README.md")
        git(self.repo, "commit", "-qm", "init")
        (self.repo / ".claude").mkdir()
        self.local = self.repo / ".claude" / "settings.local.json"

    def tearDown(self):
        shutil.rmtree(self.repo, ignore_errors=True)

    def write_local(self, *rules):
        self.local.write_text(json.dumps({"permissions": {"allow": list(rules)}}, indent=2) + "\n")

    def checks(self, result):
        return {(f.check, f.rule, f.severity) for f in result.findings}

    # ------------------------------------------------------------------

    def test_local_only_secret_is_a_warning(self):
        self.write_local("Bash(ls)", SECRET_RULE)
        r = scan(self.repo, skip={"DAA004"})
        self.assertIn(("DAA002", "env-secret-literal", "warn"), self.checks(r))
        self.assertIn(("DAA003", "gitignore-global-only", "warn"), self.checks(r))
        self.assertEqual(r.errors, [])

    def test_force_committed_file_is_an_error(self):
        self.write_local(SECRET_RULE)
        git(self.repo, "add", "-f", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "oops")
        r = scan(self.repo)
        self.assertIn(("DAA001", "local-settings-tracked", "error"), self.checks(r))
        self.assertIn(("DAA002", "env-secret-literal", "error"), self.checks(r))
        self.assertEqual(cli.main(["scan", str(self.repo), "--format", "json", "-o", str(self.repo / "r.json")]), 1)
        report = (self.repo / "r.json").read_text()
        self.assertNotIn("Tr0ub4dor-77", report)

    def test_repo_gitignore_clears_daa003(self):
        (self.repo / ".gitignore").write_text("**/.claude/settings.local.json\n")
        self.write_local("Bash(ls)")
        r = scan(self.repo)
        self.assertEqual([f for f in r.findings if f.check == "DAA003"], [])

    def test_history_finds_removed_secret(self):
        self.write_local(SECRET_RULE)
        git(self.repo, "add", "-f", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "oops")
        git(self.repo, "rm", "-q", "--cached", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "remove")
        self.write_local("Bash(ls)")  # local copy is clean now
        r = scan(self.repo, history=True)
        hist = [f for f in r.findings if f.commit and f.check == "DAA002"]
        self.assertEqual([(f.check, f.rule) for f in hist], [("DAA002", "env-secret-literal")])
        self.assertIn(("DAA001", "local-settings-in-history", "warn"), self.checks(r))
        self.assertFalse(any(f.commit for f in scan(self.repo).findings))

    def test_history_reports_each_rotated_password(self):
        # Same rule text, different password in each commit: every one needs rotating.
        for pw in ("Rot-Pass-1", "Rot-Pass-2", "Rot-Pass-3"):
            self.write_local(f"Bash(PGPASSWORD={pw} psql -h db)")
            git(self.repo, "add", "-f", ".claude/settings.local.json")
            git(self.repo, "commit", "-qm", pw)
        r = scan(self.repo, history=True)
        secrets = sorted(f.secret for f in r.findings if f.check == "DAA002")
        self.assertEqual(secrets, ["Rot-Pass-1", "Rot-Pass-2", "Rot-Pass-3"])
        self.assertEqual(sum(1 for f in r.findings if f.check == "DAA002" and f.commit is None), 1)

    def test_history_counts_commits_per_secret(self):
        for i in range(3):  # same secret, unrelated rule changes around it
            self.write_local(f"Bash(ls {i})", SECRET_RULE)
            git(self.repo, "add", "-f", ".claude/settings.local.json")
            git(self.repo, "commit", "-qm", f"c{i}")
        git(self.repo, "rm", "-q", "--cached", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "remove")
        self.local.unlink()
        [f] = [f for f in scan(self.repo, history=True).findings if f.check == "DAA002"]
        self.assertIn("present in 3 commits", f.message)

    def test_read_blobs_skips_missing(self):
        from dont_ask_again.git import read_blobs

        head = git(self.repo, "rev-parse", "HEAD").strip()
        blobs = read_blobs(self.repo, [f"{head}:README.md", f"{head}:no such file", f"{head}:README.md"])
        self.assertEqual(blobs, {f"{head}:README.md": "hi\n"})

    def test_dockerignore(self):
        self.write_local("Bash(ls)")
        (self.repo / "Dockerfile").write_text("FROM scratch\nCOPY . .\n")
        self.assertIn(("DAA003", "dockerignore-missing", "warn"), self.checks(scan(self.repo)))
        (self.repo / ".dockerignore").write_text("**/.claude\n")
        self.assertNotIn(("DAA003", "dockerignore-missing", "warn"), self.checks(scan(self.repo)))

    def test_fix_dry_run_changes_nothing(self):
        self.write_local(SECRET_RULE)
        git(self.repo, "add", "-f", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "oops")
        before = self.local.read_text()
        self.assertEqual(cli.main(["fix", str(self.repo), "--redact-local"]), 0)
        self.assertEqual(self.local.read_text(), before)
        self.assertFalse((self.repo / ".gitignore").exists())
        self.assertIn(".claude/settings.local.json", git(self.repo, "ls-files"))

    def test_fix_yes_untracks_ignores_and_redacts(self):
        self.write_local("Bash(ls)", SECRET_RULE)
        git(self.repo, "add", "-f", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "oops")
        self.assertEqual(cli.main(["fix", str(self.repo), "--redact-local", "--yes"]), 0)
        self.assertNotIn(".claude/settings.local.json", git(self.repo, "ls-files"))
        self.assertIn("**/.claude/settings.local.json", (self.repo / ".gitignore").read_text())
        data = json.loads(self.local.read_text())
        self.assertEqual(data["permissions"]["allow"], ["Bash(ls)"])
        backups = list(fix.BACKUP_DIR.iterdir())
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o600)
        # After the fix only DAA003-free, DAA002-free state remains (history aside)
        r = scan(self.repo)
        self.assertEqual([f for f in r.findings if f.check in ("DAA001", "DAA002", "DAA003")], [])

    def test_daaignore_suppresses(self):
        self.write_local(SECRET_RULE)
        fp = next(f.fingerprint for f in scan(self.repo).findings if f.check == "DAA002")
        (self.repo / ".daaignore").write_text(f"{fp}  # accepted: test fixture\n")
        self.assertFalse(any(f.check == "DAA002" for f in scan(self.repo).findings))

    def test_sarif_is_valid_json(self):
        self.write_local(SECRET_RULE)
        out = self.repo / "r.sarif"
        cli.main(["scan", str(self.repo), "--format", "sarif", "-o", str(out), "--fail-on", "never"])
        doc = json.loads(out.read_text())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertTrue(doc["runs"][0]["results"])
        self.assertNotIn("Tr0ub4dor-77", out.read_text())

    def test_sarif_flag_writes_alongside_text_in_one_run(self):
        self.write_local(SECRET_RULE)
        out = self.repo / "side.sarif"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["scan", str(self.repo), "--sarif", str(out), "--fail-on", "warn"])
        self.assertEqual(code, 1)
        self.assertIn("DAA002", buf.getvalue())
        self.assertEqual(json.loads(out.read_text())["version"], "2.1.0")

    def test_ignore_sources_batch(self):
        from dont_ask_again.git import ignore_sources, source_travels

        (self.repo / ".gitignore").write_text("*.log\n")
        got = ignore_sources(self.repo, ["a.log", ".claude/settings.local.json", "keep.txt"])
        self.assertTrue(source_travels(got["a.log"]))
        self.assertFalse(source_travels(got[".claude/settings.local.json"]))  # global excludes only
        self.assertIsNotNone(got[".claude/settings.local.json"])
        self.assertIsNone(got["keep.txt"])

    def test_skip_all_git_checks(self):
        self.write_local(SECRET_RULE)
        git(self.repo, "add", "-f", ".claude/settings.local.json")
        git(self.repo, "commit", "-qm", "oops")
        r = scan(self.repo, skip={"daa001", "DAA003", "DAA004"})
        self.assertEqual({f.check for f in r.findings}, {"DAA002"})


class NonGitTest(unittest.TestCase):
    def test_plain_directory(self):
        d = Path(tempfile.mkdtemp(prefix="daa-plain-"))
        try:
            (d / ".claude").mkdir()
            (d / ".claude" / "settings.json").write_text(json.dumps({"permissions": {"allow": [SECRET_RULE]}}))
            r = scan(d)
            self.assertEqual([(f.check, f.severity) for f in r.findings], [("DAA002", "error")])
            self.assertTrue(any("not a git repository" in n for n in r.notes))
        finally:
            shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
