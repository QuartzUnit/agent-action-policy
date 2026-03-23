"""Policy loader from YAML files and dicts."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from action_policy.policy import PolicyRule, policy_from_dict


def load_policies_from_yaml(path: str | Path) -> list[PolicyRule]:
    """Load policies from a YAML file.

    Requires PyYAML (optional dependency).
    """
    try:
        import yaml
    except ImportError as e:
        raise ImportError(
            "PyYAML is required for YAML loading. Install with: pip install agent-action-policy[yaml]"
        ) from e

    with open(path) as f:
        data = yaml.safe_load(f)

    return load_policies_from_dict(data)


def load_policies_from_dict(data: dict[str, Any]) -> list[PolicyRule]:
    """Load policies from a dict structure (e.g., already-parsed YAML)."""
    policies_data = data.get("policies", [])
    policies = [policy_from_dict(p) for p in policies_data]
    # Sort by priority (lower = higher priority)
    policies.sort(key=lambda p: p.priority)
    return policies
