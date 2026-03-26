# agent-action-policy

> [한국어 문서](README.ko.md)

Declarative action policies for AI agents — approve, deny, or escalate any tool call before execution.

## Install

```bash
pip install agent-action-policy
pip install agent-action-policy[yaml]  # for YAML policy files
```

## Quick Start

```python
from action_policy import PolicyEngine, Action

engine = PolicyEngine.from_dict({
    "policies": [{
        "name": "no-force-push",
        "match": {"tool": "bash", "args_pattern": "git push --force"},
        "action": "deny",
        "reason": "Force push requires human approval",
    }]
})

decision = engine.evaluate(tool="bash", args={"command": "git push --force origin main"})
print(decision.denied)  # True
print(decision.reason)  # "Force push requires human approval"
```

## Sandboxing vs Policy

| | Sandboxing (containers) | Policy (this library) |
|---|---|---|
| **Controls** | *Where* code runs | *What* the agent can do |
| **Granularity** | Process-level | Per-tool-call |
| **Configuration** | Infrastructure | YAML/Python |
| **Use with** | Any runtime | Any agent framework |

Sandboxing and policies are complementary. Use both.

## Policy Definition (YAML)

```yaml
policies:
  - name: no-destructive-git
    match:
      tool: bash
      args_pattern: "git (push --force|reset --hard|branch -D)"
    action: deny
    reason: "Destructive git operations require human approval"

  - name: escalate-system-files
    match:
      tool: "~(file_write|write_file)"
      path_patterns:
        - "/etc/*"
        - "/usr/*"
    action: escalate
    reason: "System file modification needs confirmation"

  - name: approve-reads
    match:
      tool: "~(read|search|grep)"
    action: approve
    priority: 10  # lower = higher priority
```

## Built-in Templates

```python
engine = PolicyEngine.from_template("safe_coding")
```

| Template | What it protects |
|----------|-----------------|
| `safe_coding` | Blocks force-push, rm -rf, system file writes, credential access, hook skipping |
| `safe_browsing` | Blocks internal URLs, file:// protocol, escalates downloads |
| `safe_database` | Blocks DDL (DROP/TRUNCATE), escalates DELETE and WHERE-less UPDATE |
| `strict` | Whitelist mode — only read operations allowed, everything else denied |

## Python API

```python
# From YAML file
engine = PolicyEngine.from_yaml("policies.yaml")

# From dict
engine = PolicyEngine.from_dict({"policies": [...]})

# From template
engine = PolicyEngine.from_template("safe_coding")

# Evaluate
decision = engine.evaluate(tool="bash", args={"command": "rm -rf /"})
decision.action     # Action.DENY
decision.denied     # True
decision.reason     # "..."
decision.policy_name  # "no-rm-rf"

# Fail-closed mode (deny by default)
engine = PolicyEngine.from_template("strict", default_action=Action.DENY)

# Decorator
@engine.guard
def execute_tool(tool: str, args: dict = None):
    ...  # raises PolicyDenied or PolicyEscalated
```

## Pattern Matching

| Pattern type | Syntax | Example |
|-------------|--------|---------|
| Exact match | `tool_name` | `"bash"` |
| Glob | `*`, `?`, `[...]` | `"file_*"` |
| Regex | `~pattern` | `"~(bash\|shell\|exec)"` |
| Args regex | any regex | `"git\\s+push\\s+--force"` |
| Path glob | glob or `~regex` | `"/etc/*"`, `"~\\.env$"` |

## Used in

- [watchdeck](https://github.com/QuartzUnit/watchdeck) — Web page monitoring with visual diffs and safety guards

## License

MIT
