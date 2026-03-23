"""Core PolicyEngine — evaluate tool calls against policies."""

from __future__ import annotations

import functools
from pathlib import Path
from typing import Any, Callable

from action_policy.decision import APPROVE_DEFAULT, Action, Decision
from action_policy.loader import load_policies_from_dict, load_policies_from_yaml
from action_policy.policy import PolicyRule


class PolicyEngine:
    """Declarative action policy engine for AI agents.

    Evaluates tool calls against a set of policies and returns
    APPROVE, DENY, or ESCALATE decisions.

    Usage:
        engine = PolicyEngine.from_yaml("policies.yaml")
        decision = engine.evaluate(tool="bash", args={"command": "rm -rf /"})
        # -> Decision(action=DENY, policy_name="no-destructive-bash", ...)

    Default behavior (no matching policy): APPROVE (open by default).
    Use `default_action=Action.DENY` for fail-closed mode.
    """

    def __init__(
        self,
        policies: list[PolicyRule] | None = None,
        default_action: Action = Action.APPROVE,
        default_reason: str = "",
    ):
        self._policies = sorted(policies or [], key=lambda p: p.priority)
        self._default_action = default_action
        self._default_reason = default_reason or (
            "No matching policy — default approve" if default_action == Action.APPROVE
            else "No matching policy — default deny (fail-closed)"
        )

    @classmethod
    def from_yaml(cls, path: str | Path, **kwargs: Any) -> PolicyEngine:
        """Load policies from a YAML file."""
        policies = load_policies_from_yaml(path)
        return cls(policies=policies, **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any], **kwargs: Any) -> PolicyEngine:
        """Load policies from a dict."""
        policies = load_policies_from_dict(data)
        return cls(policies=policies, **kwargs)

    @classmethod
    def from_template(cls, template_name: str, **kwargs: Any) -> PolicyEngine:
        """Load a built-in policy template.

        Available templates: safe_coding, safe_browsing, safe_database, strict
        """
        templates_dir = Path(__file__).parent / "templates"
        path = templates_dir / f"{template_name}.yaml"
        if not path.exists():
            available = [f.stem for f in templates_dir.glob("*.yaml")]
            raise ValueError(f"Unknown template '{template_name}'. Available: {available}")
        return cls.from_yaml(path, **kwargs)

    def evaluate(self, tool: str, args: dict[str, Any] | str | None = None) -> Decision:
        """Evaluate a tool call against all policies.

        First matching policy wins (ordered by priority).
        """
        for policy in self._policies:
            if policy.matches(tool, args):
                return policy.to_decision()

        if self._default_action == Action.APPROVE:
            return APPROVE_DEFAULT
        return Decision(
            action=self._default_action,
            policy_name="default",
            reason=self._default_reason,
        )

    def guard(self, func: Callable) -> Callable:
        """Decorator that checks policy before executing the wrapped function.

        The function must accept `tool` as its first argument and `args` as keyword.
        Raises PolicyDenied if the policy denies the action.
        """
        @functools.wraps(func)
        def wrapper(tool: str, args: dict | str | None = None, **kwargs: Any) -> Any:
            decision = self.evaluate(tool, args)
            if decision.denied:
                raise PolicyDenied(decision)
            if decision.escalated:
                raise PolicyEscalated(decision)
            return func(tool, args=args, **kwargs)
        return wrapper

    @property
    def policies(self) -> list[PolicyRule]:
        return list(self._policies)

    def add_policy(self, policy: PolicyRule) -> None:
        """Add a policy and re-sort by priority."""
        self._policies.append(policy)
        self._policies.sort(key=lambda p: p.priority)


class PolicyDenied(Exception):
    """Raised when a policy denies an action."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Policy '{decision.policy_name}' denied: {decision.reason}")


class PolicyEscalated(Exception):
    """Raised when a policy requires human escalation."""

    def __init__(self, decision: Decision):
        self.decision = decision
        super().__init__(f"Policy '{decision.policy_name}' requires escalation: {decision.reason}")
