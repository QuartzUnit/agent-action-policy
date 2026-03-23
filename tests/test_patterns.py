"""Tests for pattern matching utilities."""

from action_policy.patterns import match_args, match_path, match_tool


class TestMatchTool:
    def test_exact_match(self):
        assert match_tool("bash", "bash")
        assert not match_tool("bash", "shell")

    def test_glob_wildcard(self):
        assert match_tool("file_write", "file_*")
        assert match_tool("file_read", "file_*")
        assert not match_tool("bash", "file_*")

    def test_glob_question_mark(self):
        assert match_tool("bash", "bas?")
        assert not match_tool("bash", "ba?")

    def test_regex_prefix(self):
        assert match_tool("bash", "~(bash|shell|exec)")
        assert match_tool("shell", "~(bash|shell|exec)")
        assert not match_tool("read", "~(bash|shell|exec)")

    def test_regex_partial(self):
        assert match_tool("file_write", "~file_")
        assert match_tool("file_read", "~file_")


class TestMatchArgs:
    def test_dict_args(self):
        assert match_args({"command": "git push --force"}, "git push --force")
        assert not match_args({"command": "git status"}, "git push --force")

    def test_string_args(self):
        assert match_args("git push --force origin", "git push --force")
        assert not match_args("git status", "git push --force")

    def test_none_args(self):
        assert not match_args(None, "anything")

    def test_regex_pattern(self):
        assert match_args({"cmd": "rm -rf /"}, r"rm\s+-[rf]{2,}")
        assert match_args({"cmd": "rm -fr /tmp"}, r"rm\s+-[rf]{2,}")

    def test_complex_regex(self):
        assert match_args(
            {"command": "git push --force origin main"},
            r"git\s+push\s+--force.*\b(main|master)\b",
        )


class TestMatchPath:
    def test_glob_pattern(self):
        assert match_path("/etc/passwd", ["/etc/*"])
        assert not match_path("/home/user/file", ["/etc/*"])

    def test_multiple_patterns(self):
        assert match_path("/usr/bin/python", ["/etc/*", "/usr/*"])
        assert match_path("/etc/hosts", ["/etc/*", "/usr/*"])
        assert not match_path("/home/user", ["/etc/*", "/usr/*"])

    def test_regex_pattern(self):
        assert match_path("/home/user/.env", [r"~\.env$"])
        assert not match_path("/home/user/.envrc", [r"~\.env$"])

    def test_ssh_pattern(self):
        assert match_path("/home/user/.ssh/id_rsa", ["~\\.ssh/"])

    def test_empty_patterns(self):
        assert not match_path("/any/path", [])
