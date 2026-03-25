# agent-action-policy

> [English](README.md)

AI 에이전트를 위한 선언적 액션 정책 — 도구 호출 전에 승인, 거부, 또는 에스컬레이션합니다.

## 설치

```bash
pip install agent-action-policy
pip install agent-action-policy[yaml]  # YAML 정책 파일 지원
```

## 빠른 시작

```python
from action_policy import PolicyEngine, Action

engine = PolicyEngine.from_dict({
    "policies": [{
        "name": "no-force-push",
        "match": {"tool": "bash", "args_pattern": "git push --force"},
        "action": "deny",
        "reason": "Force push는 사람의 승인이 필요합니다",
    }]
})

decision = engine.evaluate(tool="bash", args={"command": "git push --force origin main"})
print(decision.denied)  # True
print(decision.reason)  # "Force push는 사람의 승인이 필요합니다"
```

## 샌드박싱 vs 정책

| | 샌드박싱 (컨테이너) | 정책 (이 라이브러리) |
|---|---|---|
| **제어 대상** | 코드가 *어디서* 실행되는지 | 에이전트가 *무엇을* 할 수 있는지 |
| **세분성** | 프로세스 수준 | 도구 호출 단위 |
| **설정 방식** | 인프라 | YAML/Python |
| **사용 대상** | 모든 런타임 | 모든 에이전트 프레임워크 |

샌드박싱과 정책은 상호 보완적입니다. 둘 다 사용하세요.

## 정책 정의 (YAML)

```yaml
policies:
  - name: no-destructive-git
    match:
      tool: bash
      args_pattern: "git (push --force|reset --hard|branch -D)"
    action: deny
    reason: "파괴적 git 작업은 사람의 승인이 필요합니다"

  - name: escalate-system-files
    match:
      tool: "~(file_write|write_file)"
      path_patterns:
        - "/etc/*"
        - "/usr/*"
    action: escalate
    reason: "시스템 파일 수정은 확인이 필요합니다"

  - name: approve-reads
    match:
      tool: "~(read|search|grep)"
    action: approve
    priority: 10  # 낮을수록 높은 우선순위
```

## 내장 템플릿

```python
engine = PolicyEngine.from_template("safe_coding")
```

| 템플릿 | 보호 대상 |
|--------|----------|
| `safe_coding` | force-push, rm -rf, 시스템 파일 쓰기, 자격증명 접근, 훅 우회 차단 |
| `safe_browsing` | 내부 URL, file:// 프로토콜 차단, 다운로드 에스컬레이션 |
| `safe_database` | DDL (DROP/TRUNCATE) 차단, DELETE 및 WHERE 없는 UPDATE 에스컬레이션 |
| `strict` | 화이트리스트 모드 — 읽기 작업만 허용, 나머지 전부 거부 |

## Python API

```python
# YAML 파일에서
engine = PolicyEngine.from_yaml("policies.yaml")

# dict에서
engine = PolicyEngine.from_dict({"policies": [...]})

# 템플릿에서
engine = PolicyEngine.from_template("safe_coding")

# 평가
decision = engine.evaluate(tool="bash", args={"command": "rm -rf /"})
decision.action     # Action.DENY
decision.denied     # True
decision.reason     # "..."
decision.policy_name  # "no-rm-rf"

# 기본 거부 모드 (fail-closed)
engine = PolicyEngine.from_template("strict", default_action=Action.DENY)

# 데코레이터
@engine.guard
def execute_tool(tool: str, args: dict = None):
    ...  # PolicyDenied 또는 PolicyEscalated 예외 발생
```

## 패턴 매칭

| 패턴 유형 | 문법 | 예시 |
|----------|------|------|
| 정확 매치 | `tool_name` | `"bash"` |
| 글로브 | `*`, `?`, `[...]` | `"file_*"` |
| 정규식 | `~pattern` | `"~(bash\|shell\|exec)"` |
| 인자 정규식 | 모든 정규식 | `"git\\s+push\\s+--force"` |
| 경로 글로브 | glob 또는 `~regex` | `"/etc/*"`, `"~\\.env$"` |

## 라이선스

MIT
