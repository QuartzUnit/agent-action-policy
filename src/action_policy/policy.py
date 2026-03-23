"""Policy definition and matching logic."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from action_policy.decision import Action, Decision
from action_policy.patterns import match_args, match_path, match_tool


@dataclass(frozen=True)
class PolicyRule:
    """A single policy rule.

    Attributes:
        name: Human-readable policy name.
        action: What to do when matched (APPROVE, DENY, ESCALATE).
        reason: Explanation for why this policy exists.
        tool_pattern: Pattern to match tool names (exact, glob, or ~regex).
        args_pattern: Regex pattern to match against stringified args.
        path_patterns: List of glob/regex patterns to match file paths in args.
        priority: Lower number = higher priority. Default 100.
    """

    name: str
    action: Action
    reason: str = ""
    tool_pattern: str = "*"
    args_pattern: str | None = None
    path_patterns: tuple[str, ...] = field(default_factory=tuple)
    priority: int = 100

    def matches(self, tool: str, args: dict[str, Any] | str | None = None) -> bool:
        """Check if this policy matches the given tool call."""
        if not match_tool(tool, self.tool_pattern):
            return False

        if self.args_pattern and not match_args(args, self.args_pattern):
            return False

        if self.path_patterns:
            path = _extract_path(args)
            if path and not match_path(path, list(self.path_patterns)):
                return False
            if not path:
                return False

        return True

    def to_decision(self) -> Decision:
        return Decision(action=self.action, policy_name=self.name, reason=self.reason)


def _extract_path(args: dict | str | None) -> str:
    """Try to extract a file path from args."""
    if isinstance(args, dict):
        for key in ("path", "file_path", "filename", "file", "filepath"):
            if key in args:
                return str(args[key])
    if isinstance(args, str):
        return args
    return ""


def policy_from_dict(data: dict[str, Any]) -> PolicyRule:
    """Create a PolicyRule from a dict (e.g., parsed YAML)."""
    action_str = data.get("action", "deny").upper()
    action = Action[action_str]

    match_block = data.get("match", {})
    path_patterns = match_block.get("path_patterns", [])
    if isinstance(path_patterns, str):
        path_patterns = [path_patterns]

    return PolicyRule(
        name=data["name"],
        action=action,
        reason=data.get("reason", ""),
        tool_pattern=match_block.get("tool", "*"),
        args_pattern=match_block.get("args_pattern"),
        path_patterns=tuple(path_patterns),
        priority=data.get("priority", 100),
    )
