"""Decision types for policy evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class Action(Enum):
    """Policy evaluation result."""

    APPROVE = auto()
    DENY = auto()
    ESCALATE = auto()


@dataclass(frozen=True, slots=True)
class Decision:
    """Result of a policy evaluation."""

    action: Action
    policy_name: str = ""
    reason: str = ""

    @property
    def approved(self) -> bool:
        return self.action == Action.APPROVE

    @property
    def denied(self) -> bool:
        return self.action == Action.DENY

    @property
    def escalated(self) -> bool:
        return self.action == Action.ESCALATE


# Singleton for default approve (no policy matched)
APPROVE_DEFAULT = Decision(action=Action.APPROVE, policy_name="", reason="No matching policy — default approve")
