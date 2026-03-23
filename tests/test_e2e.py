"""End-to-end tests — realistic agent policy scenarios."""

import pytest

from action_policy import Action, PolicyDenied, PolicyEngine, PolicyEscalated, PolicyRule


class TestRealWorldPolicies:
    """Simulate actual agent safety scenarios from OpenHands/CrewAI/AutoGen issues."""

    def test_openhands_13150_sandbox_escape(self):
        """OpenHands #13150: Agent uses bash to bypass sandbox."""
        engine = PolicyEngine.from_template("safe_coding")

        # Normal development commands — should pass
        assert engine.evaluate("bash", {"command": "python main.py"}).approved
        assert engine.evaluate("bash", {"command": "pip install requests"}).approved
        assert engine.evaluate("bash", {"command": "git add ."}).approved
        assert engine.evaluate("bash", {"command": "git commit -m 'fix'"}).approved

        # Dangerous commands — should block
        assert engine.evaluate("bash", {"command": "git push --force origin main"}).denied
        assert engine.evaluate("bash", {"command": "git reset --hard HEAD~5"}).denied
        assert engine.evaluate("bash", {"command": "rm -rf /home/user/project"}).escalated
        assert engine.evaluate("bash", {"command": "git commit --no-verify"}).denied

    def test_autogen_7230_tool_safety(self):
        """AutoGen #7230: ToolSafetyPolicy interface — compose multiple templates."""
        # Combine safe_coding + safe_database
        coding = PolicyEngine.from_template("safe_coding")
        db = PolicyEngine.from_template("safe_database")

        # Build combined engine
        all_policies = coding.policies + db.policies
        engine = PolicyEngine(policies=all_policies)

        # Coding safety
        assert engine.evaluate("bash", {"command": "git push --force"}).denied
        # DB safety
        assert engine.evaluate("sql", {"query": "DROP TABLE users"}).denied
        # Normal ops
        assert engine.evaluate("bash", {"command": "pytest tests/"}).approved
        assert engine.evaluate("sql", {"query": "SELECT * FROM users"}).approved

    def test_crewai_4593_fail_closed(self):
        """CrewAI #4593: Fail-closed defaults for unsafe tools."""
        engine = PolicyEngine.from_template("strict", default_action=Action.DENY)

        # Only read operations allowed
        assert engine.evaluate("read", {"path": "file.py"}).approved
        assert engine.evaluate("search", {"query": "function def"}).approved
        assert engine.evaluate("grep", {"pattern": "TODO"}).approved

        # Everything else denied
        assert engine.evaluate("bash", {"command": "echo hi"}).denied
        assert engine.evaluate("file_write", {"path": "x.py"}).denied
        assert engine.evaluate("http_request", {"url": "https://evil.com"}).denied

    def test_ssrf_prevention(self):
        """Prevent SSRF via internal URL access."""
        engine = PolicyEngine.from_template("safe_browsing")

        # Block internal URLs
        assert engine.evaluate("web_fetch", {"url": "http://localhost:8080/admin"}).denied
        assert engine.evaluate("web_fetch", {"url": "http://127.0.0.1:9000/api"}).denied
        assert engine.evaluate("web_fetch", {"url": "http://169.254.169.254/latest/meta-data"}).denied
        assert engine.evaluate("fetch", {"url": "file:///etc/passwd"}).denied

        # Allow normal URLs
        assert engine.evaluate("web_fetch", {"url": "https://api.github.com/repos"}).approved

    def test_credential_protection(self):
        """Prevent reading sensitive files."""
        engine = PolicyEngine.from_template("safe_coding")

        assert engine.evaluate("file_read", {"path": "/home/user/.env"}).escalated
        assert engine.evaluate("read_file", {"path": "/home/user/.ssh/id_rsa"}).escalated
        assert engine.evaluate("read", {"path": "/home/user/.aws/credentials"}).escalated

        # Normal files OK
        assert engine.evaluate("file_read", {"path": "/home/user/code.py"}).approved

    def test_sql_injection_prevention(self):
        """Prevent destructive SQL operations."""
        engine = PolicyEngine.from_template("safe_database")

        # Destructive DDL blocked
        assert engine.evaluate("query", {"query": "DROP TABLE users CASCADE"}).denied
        assert engine.evaluate("database", {"query": "TRUNCATE TABLE logs"}).denied
        assert engine.evaluate("sql", {"query": "ALTER TABLE users DROP COLUMN email"}).denied

        # DML needs confirmation
        assert engine.evaluate("sql", {"query": "DELETE FROM sessions WHERE expired=true"}).escalated

        # Safe queries pass
        assert engine.evaluate("sql", {"query": "SELECT count(*) FROM users"}).approved
        assert engine.evaluate("sql", {"query": "INSERT INTO logs (msg) VALUES ('test')"}).approved

    def test_runtime_policy_addition(self):
        """Add policies dynamically during agent execution."""
        engine = PolicyEngine.from_template("safe_coding")

        # Initially, custom tool is allowed
        assert engine.evaluate("deploy", {"target": "production"}).approved

        # Ops team adds a policy at runtime
        engine.add_policy(PolicyRule(
            name="no-prod-deploy",
            action=Action.ESCALATE,
            tool_pattern="deploy",
            args_pattern="production",
            reason="Production deployment requires ops approval",
            priority=5,
        ))

        # Now it requires escalation
        assert engine.evaluate("deploy", {"target": "production"}).escalated
        # Staging still OK
        assert engine.evaluate("deploy", {"target": "staging"}).approved

    def test_guard_decorator_flow(self):
        """Decorator integration for tool execution."""
        engine = PolicyEngine.from_template("safe_coding")
        executed = []

        @engine.guard
        def run_tool(tool, args=None):
            executed.append(tool)
            return f"executed {tool}"

        # Safe tool executes
        result = run_tool("bash", args={"command": "pytest"})
        assert result == "executed bash"
        assert "bash" in executed

        # Dangerous tool raises
        with pytest.raises(PolicyDenied):
            run_tool("bash", args={"command": "git push --force main"})

        with pytest.raises(PolicyEscalated):
            run_tool("bash", args={"command": "rm -rf /tmp"})

    def test_priority_ordering(self):
        """Higher priority rules override lower priority."""
        engine = PolicyEngine.from_dict({
            "policies": [
                {
                    "name": "allow-specific-deploy",
                    "match": {"tool": "deploy", "args_pattern": "canary"},
                    "action": "approve",
                    "reason": "Canary deployments are safe",
                    "priority": 5,
                },
                {
                    "name": "block-all-deploy",
                    "match": {"tool": "deploy"},
                    "action": "deny",
                    "reason": "Deployments blocked",
                    "priority": 10,
                },
            ]
        })

        # Canary deploy should be approved (higher priority rule)
        assert engine.evaluate("deploy", {"type": "canary"}).approved
        # Other deploys blocked
        assert engine.evaluate("deploy", {"type": "full"}).denied

    def test_multiple_arg_patterns(self):
        """Complex regex patterns in args matching."""
        engine = PolicyEngine.from_dict({
            "policies": [{
                "name": "block-env-manipulation",
                "match": {
                    "tool": "bash",
                    "args_pattern": r"(export|unset|env)\s+\w*(?:KEY|SECRET|TOKEN|PASSWORD)",
                },
                "action": "deny",
                "reason": "Environment variable manipulation with secrets blocked",
            }]
        })

        assert engine.evaluate("bash", {"command": "export API_KEY=abc123"}).denied
        assert engine.evaluate("bash", {"command": "unset SECRET_TOKEN"}).denied
        assert engine.evaluate("bash", {"command": "export PATH=/usr/bin"}).approved
