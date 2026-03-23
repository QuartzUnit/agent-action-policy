"""Pattern matching utilities for policy rules."""

from __future__ import annotations

import fnmatch
import re
from functools import lru_cache


@lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern:
    """Compile and cache a regex pattern."""
    return re.compile(pattern)


def match_tool(tool_name: str, pattern: str) -> bool:
    """Match a tool name against a pattern.

    Supports:
      - Exact match: "bash"
      - Glob: "file_*"
      - Regex (prefixed with ~): "~(bash|shell|exec)"
    """
    if pattern.startswith("~"):
        return bool(_compile_regex(pattern[1:]).search(tool_name))
    if any(c in pattern for c in ("*", "?", "[")):
        return fnmatch.fnmatch(tool_name, pattern)
    return tool_name == pattern


def match_args(args: dict | str | None, pattern: str) -> bool:
    """Match tool arguments against a pattern.

    The pattern is matched against the string representation of args.
    Supports:
      - Regex (always): searches the stringified args
    """
    if args is None:
        return False
    text = _stringify_args(args)
    try:
        return bool(_compile_regex(pattern).search(text))
    except re.error:
        return False


def match_path(path: str, patterns: list[str]) -> bool:
    """Match a file path against a list of glob/regex patterns.

    Each pattern can be:
      - Glob: "/etc/*", "~/.ssh/*"
      - Regex (prefixed with ~): "~\\.env$"
    """
    for pat in patterns:
        if pat.startswith("~"):
            if _compile_regex(pat[1:]).search(path):
                return True
        elif fnmatch.fnmatch(path, pat):
            return True
    return False


def _stringify_args(args: dict | str | None) -> str:
    """Convert args to string for pattern matching."""
    if args is None:
        return ""
    if isinstance(args, str):
        return args
    if isinstance(args, dict):
        parts = []
        for k, v in sorted(args.items()):
            parts.append(f"{k}={v}")
        return " ".join(parts)
    return str(args)
