"""Tests for built-in policy templates."""

import pytest

from action_policy import Action, PolicyEngine


class TestSafeCoding:
    def setup_method(self):
        self.engine = PolicyEngine.from_template("safe_coding")

    def test_blocks_force_push(self):
        d = self.engine.evaluate("bash", {"command": "git push --force origin main"})
        assert d.denied

    def test_blocks_reset_hard(self):
        d = self.engine.evaluate("bash", {"command": "git reset --hard HEAD~1"})
        assert d.denied

    def test_blocks_branch_delete(self):
        d = self.engine.evaluate("bash", {"command": "git branch -D feature"})
        assert d.denied

    def test_blocks_clean_fd(self):
        d = self.engine.evaluate("bash", {"command": "git clean -fd"})
        assert d.denied

    def test_escalates_rm_rf(self):
        d = self.engine.evaluate("bash", {"command": "rm -rf /tmp/build"})
        assert d.escalated

    def test_blocks_system_file_write(self):
        d = self.engine.evaluate("file_write", {"path": "/etc/hosts", "content": "x"})
        assert d.denied

    def test_escalates_credential_read(self):
        d = self.engine.evaluate("file_read", {"path": "/home/user/.env"})
        assert d.escalated

    def test_escalates_ssh_key_read(self):
        d = self.engine.evaluate("read_file", {"path": "/home/user/.ssh/id_rsa"})
        assert d.escalated

    def test_blocks_no_verify(self):
        d = self.engine.evaluate("bash", {"command": "git commit --no-verify -m 'skip'"})
        assert d.denied

    def test_allows_normal_git(self):
        d = self.engine.evaluate("bash", {"command": "git status"})
        assert d.approved

    def test_allows_normal_file_write(self):
        d = self.engine.evaluate("file_write", {"path": "/home/user/code.py", "content": "x"})
        assert d.approved


class TestSafeBrowsing:
    def setup_method(self):
        self.engine = PolicyEngine.from_template("safe_browsing")

    def test_blocks_localhost(self):
        d = self.engine.evaluate("web_fetch", {"url": "http://localhost:8080/admin"})
        assert d.denied

    def test_blocks_internal_ip(self):
        d = self.engine.evaluate("http_request", {"url": "http://169.254.169.254/metadata"})
        assert d.denied

    def test_blocks_file_protocol(self):
        d = self.engine.evaluate("fetch", {"url": "file:///etc/passwd"})
        assert d.denied

    def test_allows_normal_url(self):
        d = self.engine.evaluate("web_fetch", {"url": "https://example.com"})
        assert d.approved


class TestSafeDatabase:
    def setup_method(self):
        self.engine = PolicyEngine.from_template("safe_database")

    def test_blocks_drop_table(self):
        d = self.engine.evaluate("sql", {"query": "DROP TABLE users"})
        assert d.denied

    def test_blocks_truncate(self):
        d = self.engine.evaluate("database", {"query": "TRUNCATE TABLE logs"})
        assert d.denied

    def test_escalates_delete(self):
        d = self.engine.evaluate("sql", {"query": "DELETE FROM users WHERE id=1"})
        assert d.escalated

    def test_allows_select(self):
        d = self.engine.evaluate("sql", {"query": "SELECT * FROM users WHERE id=1"})
        assert d.approved


class TestStrict:
    def setup_method(self):
        self.engine = PolicyEngine.from_template("strict", default_action=Action.DENY)

    def test_allows_read(self):
        d = self.engine.evaluate("read", {"path": "file.py"})
        assert d.approved

    def test_allows_search(self):
        d = self.engine.evaluate("search", {"query": "test"})
        assert d.approved

    def test_denies_write(self):
        d = self.engine.evaluate("file_write", {"path": "file.py"})
        assert d.denied

    def test_denies_bash(self):
        d = self.engine.evaluate("bash", {"command": "echo hi"})
        assert d.denied


class TestTemplateNotFound:
    def test_unknown_template(self):
        with pytest.raises(ValueError, match="Unknown template"):
            PolicyEngine.from_template("nonexistent")
