"""Tests for PolicyEngine."""

import pytest

from action_policy import Action, Decision, PolicyDenied, PolicyEngine, PolicyEscalated, PolicyRule

SAMPLE_POLICIES = {
    "policies": [
        {
            "name": "no-force-push",
            "match": {"tool": "bash", "args_pattern": r"git\s+push\s+--force"},
            "action": "deny",
            "reason": "Force push requires human approval",
            "priority": 10,
        },
        {
            "name": "no-rm-rf",
            "match": {"tool": "bash", "args_pattern": r"rm\s+-[rf]{2,}"},
            "action": "escalate",
            "reason": "Recursive deletion needs confirmation",
            "priority": 10,
        },
        {
            "name": "no-system-writes",
            "match": {
                "tool": "~(file_write|write_file)",
                "path_patterns": ["/etc/*", "/usr/*"],
            },
            "action": "deny",
            "reason": "System file writes blocked",
            "priority": 20,
        },
        {
            "name": "approve-reads",
            "match": {"tool": "~(read|search|grep)"},
            "action": "approve",
            "reason": "Read-only operations allowed",
            "priority": 50,
        },
    ]
}


class TestEngineEvaluation:
    def setup_method(self):
        self.engine = PolicyEngine.from_dict(SAMPLE_POLICIES)

    def test_deny_force_push(self):
        d = self.engine.evaluate("bash", {"command": "git push --force origin main"})
        assert d.denied
        assert d.policy_name == "no-force-push"
        assert "Force push" in d.reason

    def test_escalate_rm_rf(self):
        d = self.engine.evaluate("bash", {"command": "rm -rf /tmp/build"})
        assert d.escalated
        assert d.policy_name == "no-rm-rf"

    def test_deny_system_write(self):
        d = self.engine.evaluate("file_write", {"path": "/etc/passwd", "content": "hack"})
        assert d.denied
        assert d.policy_name == "no-system-writes"

    def test_approve_read(self):
        d = self.engine.evaluate("read", {"path": "/home/user/file.py"})
        assert d.approved
        assert d.policy_name == "approve-reads"

    def test_approve_search(self):
        d = self.engine.evaluate("search", {"query": "function definition"})
        assert d.approved

    def test_default_approve_no_match(self):
        d = self.engine.evaluate("unknown_tool", {})
        assert d.approved
        assert d.policy_name == ""

    def test_normal_git_allowed(self):
        d = self.engine.evaluate("bash", {"command": "git status"})
        assert d.approved

    def test_normal_write_allowed(self):
        d = self.engine.evaluate("file_write", {"path": "/home/user/code.py", "content": "print('hi')"})
        assert d.approved

    def test_string_args(self):
        d = self.engine.evaluate("bash", "git push --force origin main")
        assert d.denied

    def test_none_args_no_crash(self):
        d = self.engine.evaluate("bash", None)
        assert d.approved  # no pattern matches None


class TestFailClosed:
    def test_default_deny(self):
        engine = PolicyEngine.from_dict(SAMPLE_POLICIES, default_action=Action.DENY)
        d = engine.evaluate("unknown_tool", {})
        assert d.denied
        assert "fail-closed" in d.reason

    def test_explicit_approve_still_works(self):
        engine = PolicyEngine.from_dict(SAMPLE_POLICIES, default_action=Action.DENY)
        d = engine.evaluate("read", {"path": "file.py"})
        assert d.approved


class TestPriority:
    def test_higher_priority_wins(self):
        data = {
            "policies": [
                {"name": "allow-all-bash", "match": {"tool": "bash"}, "action": "approve", "priority": 100},
                {"name": "deny-rm", "match": {"tool": "bash", "args_pattern": "rm"}, "action": "deny", "priority": 10},
            ]
        }
        engine = PolicyEngine.from_dict(data)
        # Higher priority (lower number) deny should win
        d = engine.evaluate("bash", {"command": "rm -rf /"})
        assert d.denied
        assert d.policy_name == "deny-rm"

    def test_same_priority_first_wins(self):
        data = {
            "policies": [
                {"name": "p1", "match": {"tool": "bash"}, "action": "deny", "priority": 50},
                {"name": "p2", "match": {"tool": "bash"}, "action": "approve", "priority": 50},
            ]
        }
        engine = PolicyEngine.from_dict(data)
        d = engine.evaluate("bash", {})
        assert d.policy_name == "p1"  # first in list at same priority


class TestGuardDecorator:
    def test_deny_raises_policy_denied(self):
        engine = PolicyEngine.from_dict(SAMPLE_POLICIES)

        @engine.guard
        def execute(tool, args=None):
            return "executed"

        with pytest.raises(PolicyDenied) as exc_info:
            execute("bash", args={"command": "git push --force"})
        assert "no-force-push" in str(exc_info.value)

    def test_escalate_raises_policy_escalated(self):
        engine = PolicyEngine.from_dict(SAMPLE_POLICIES)

        @engine.guard
        def execute(tool, args=None):
            return "executed"

        with pytest.raises(PolicyEscalated):
            execute("bash", args={"command": "rm -rf /tmp"})

    def test_approve_executes(self):
        engine = PolicyEngine.from_dict(SAMPLE_POLICIES)

        @engine.guard
        def execute(tool, args=None):
            return "executed"

        result = execute("read", args={"path": "file.py"})
        assert result == "executed"


class TestAddPolicy:
    def test_add_policy_runtime(self):
        engine = PolicyEngine()
        d = engine.evaluate("dangerous", {})
        assert d.approved  # no policies yet

        engine.add_policy(PolicyRule(
            name="block-dangerous",
            action=Action.DENY,
            tool_pattern="dangerous",
            reason="Blocked at runtime",
        ))
        d = engine.evaluate("dangerous", {})
        assert d.denied


class TestDecision:
    def test_properties(self):
        d = Decision(Action.APPROVE, "p", "r")
        assert d.approved and not d.denied and not d.escalated

        d = Decision(Action.DENY, "p", "r")
        assert d.denied and not d.approved and not d.escalated

        d = Decision(Action.ESCALATE, "p", "r")
        assert d.escalated and not d.approved and not d.denied

    def test_frozen(self):
        d = Decision(Action.APPROVE, "p", "r")
        with pytest.raises(AttributeError):
            d.action = Action.DENY  # type: ignore[misc]
