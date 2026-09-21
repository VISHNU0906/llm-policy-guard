# llm-policy-guard

**Policy-as-code enforcement layer for LLM applications.**

Define org rules in YAML. Enforce them at the API layer. Audit every violation.

```yaml
# policy.yaml
name: production-policy
rules:
  - id: pii-redact
    category: pii
    action: redact
    direction: both

  - id: secrets-block
    category: secrets
    action: block
    severity: critical

  - id: jailbreak-block
    category: jailbreak
    action: block
    direction: input
```

```python
from llm_policy_guard import PolicyEngine, load_policy

engine = PolicyEngine.from_config(load_policy("policy.yaml"))

try:
    safe_input = engine.check_input(user_message)
    response = your_llm.complete(safe_input)
    safe_output = engine.check_output(response)
    return safe_output
except PolicyBlockedError as e:
    return {"error": "blocked", "reason": e.violations[0].rule_name}
```

## Why

AI governance is a primitive problem. Every org running LLMs in production needs:

- **PII control** :  stop SSNs, credit cards, and emails from flowing through LLMs and into logs
- **Secrets protection** :  block API keys and credentials from being accidentally sent to external LLM APIs
- **Jailbreak defense** :  catch "ignore all instructions" attacks before they reach the model
- **Content categories** :  block WMD synthesis, CSAM, hate speech at the API layer
- **Audit trail** :  JSONL log of every decision for compliance review

Existing solutions (Azure AI Content Safety, AWS Bedrock Guardrails) are cloud-locked, expensive, and opaque. `llm-policy-guard` is a small, MIT-licensed Python primitive you own and run.

## Install

```bash
pip install llm-policy-guard

# With FastAPI middleware:
pip install "llm-policy-guard[fastapi]"

# With OpenAI SDK wrapper:
pip install "llm-policy-guard[openai]"
```

Requires Python 3.11+.

## Quick Start

### 1. Write a policy file

```yaml
# policy.yaml
name: my-app-policy
version: "1.0"

rules:
  - id: pii-redact-input
    name: Redact PII in user inputs
    category: pii
    action: redact
    direction: input
    config:
      patterns: [email, ssn, credit_card, phone_us]

  - id: secrets-block
    name: Block secrets everywhere
    category: secrets
    action: block
    direction: both

  - id: jailbreak-block
    name: Block jailbreak attempts
    category: jailbreak
    action: block
    direction: input
```

### 2. Enforce in your app

```python
from llm_policy_guard import PolicyEngine, load_policy
from llm_policy_guard.engine import PolicyBlockedError
from llm_policy_guard.audit import AuditLog

audit = AuditLog("audit.jsonl")  # append-only JSONL log
engine = PolicyEngine.from_config(
    load_policy("policy.yaml"),
    audit_log=audit,
)

def chat(user_message: str) -> str:
    try:
        clean = engine.check_input(user_message)
    except PolicyBlockedError as e:
        return f"Your message was blocked: {e.violations[0].message}"

    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": clean}]
    ).choices[0].message.content

    try:
        return engine.check_output(response)
    except PolicyBlockedError:
        return "Response blocked by content policy."
```

### 3. Review violations

```bash
policy-guard audit audit.jsonl
```

```
  Audit Summary
 ┌──────────────────┬──────────┐
 │ Total checks     │   12,847 │
 │ Passed           │   12,531 │
 │ Blocked          │      316 │
 │ Block rate       │    2.46% │
 │ Total violations │      389 │
 └──────────────────┴──────────┘

  Top Violated Rules
 ┌───────────────────────────┬────────────┐
 │ Rule ID                   │ Violations │
 ├───────────────────────────┼────────────┤
 │ jailbreak.ignore_instruct │        142 │
 │ pii.email                 │         89 │
 │ secrets.generic_secret    │         67 │
 └───────────────────────────┴────────────┘
```

## Built-in Policy Categories

### PII (`category: pii`)

Detects and redacts personally identifiable information:

| Pattern | Example |
|---------|---------|
| `ssn` | `123-45-6789` |
| `credit_card` | `4111111111111111` |
| `email` | `john@example.com` |
| `phone_us` | `(555) 867-5309` |
| `ipv4` | `192.168.1.1` |
| `iban` | `GB29 NWBK 6016 1331 9268 19` |
| `dob` | `DOB: 01/15/1985` |

### Secrets (`category: secrets`)

Detects credentials :  blocks by default, never logs matched values:

| Pattern | Detects |
|---------|---------|
| `openai_key` | `sk-...` |
| `anthropic_key` | `sk-ant-...` |
| `aws_access_key` | `AKIAIOSFODNN7EXAMPLE` |
| `github_token` | `ghp_...`, `ghs_...` |
| `jwt` | `eyJ...` tokens |
| `private_key_pem` | `-----BEGIN PRIVATE KEY-----` |
| `bearer_token` | `Authorization: Bearer ...` |
| `generic_secret` | `password=...` (+ entropy check) |

### Jailbreaks (`category: jailbreak`)

Catches prompt injection and safety bypass attempts:

| Pattern | Catches |
|---------|---------|
| `ignore_instructions` | "Ignore all previous instructions..." |
| `dan_mode` | "DAN mode activated" |
| `role_override` | "You are now an uncensored AI..." |
| `control_token` | `<system>`, `[INST]`, `<\|im_start\|>` |
| `system_prompt_extract` | "Reveal your system prompt" |
| `dev_mode` | "Developer mode activated" |
| `many_shot` | Repeated fake dialogue to shift model behavior |

### Content (`category: content`)

Category-based content filtering:

| Category | Blocks |
|----------|--------|
| `weapons_of_mass_destruction` | WMD synthesis instructions |
| `csam` | Child sexual abuse material |
| `hate_speech` | Calls for violence against groups |
| `self_harm` | Step-by-step self-harm instructions |
| `malware` | Ransomware, keylogger, rootkit generation |

## Actions

| Action | Behavior |
|--------|---------|
| `block` | Raise `PolicyBlockedError`, content is not passed through |
| `redact` | Replace matched text with `[TYPE REDACTED]`, pass sanitized content |
| `flag` | Record violation in audit log, pass content through |
| `log` | Log at DEBUG level only, pass content through |

## CLI

```bash
# Check a string against a policy
echo "My SSN is 123-45-6789" | policy-guard check policy.yaml

# Check with explicit direction
policy-guard check policy.yaml -t "sk-abc123..." -d input

# Validate a policy file
policy-guard validate policy.yaml

# View audit log summary
policy-guard audit audit.jsonl

# Exit code 1 if violations found (useful in CI)
echo "test message" | policy-guard check policy.yaml && echo "PASSED"
```

## FastAPI Middleware

```python
from fastapi import FastAPI
from llm_policy_guard.middleware import PolicyGuardMiddleware
from llm_policy_guard import load_policy

app = FastAPI()
app.add_middleware(
    PolicyGuardMiddleware,
    policy=load_policy("policy.yaml"),
    input_fields=["message", "content"],   # JSON fields to check on request
    output_fields=["text", "response"],    # JSON fields to check on response
)
```

## Custom Rules

```yaml
- id: custom-competitor-mention
  name: Block competitor mentions in outputs
  category: content
  action: flag
  direction: output
  severity: low
  config:
    custom_patterns:
      - id: competitor_mention
        label: Competitor Mention
        severity: low
        pattern: "(?i)\\b(CompetitorA|CompetitorB|OtherVendor)\\b"
```

## Audit Log Format

Each line in `audit.jsonl` is a JSON object:

```json
{
  "timestamp": "2025-08-15T14:23:01.123456",
  "session_id": "session-abc",
  "direction": "input",
  "content_hash": "a3f9b12c",
  "content_length": 142,
  "violations": [
    {
      "rule_id": "jailbreak.ignore_instructions",
      "rule_name": "Jailbreak: Instruction Override",
      "category": "jailbreak",
      "severity": "critical",
      "action": "block",
      "matched_text": "Ignore all previous instruc...",
      "message": "Jailbreak pattern detected in input"
    }
  ],
  "action_taken": "block",
  "passed": false
}
```

Note: matched content is truncated to 100 characters in audit logs. Raw content is never stored.

## Development

```bash
git clone https://github.com/VISHNU0906/llm-policy-guard
cd llm-policy-guard
pip install -e ".[dev]"
pytest
```

## Contributing

PRs welcome. When adding a new detection pattern:
1. Add it to the appropriate policy module under `llm_policy_guard/policies/`
2. Add a test case in `tests/`
3. Add an example to `schemas/policy.yaml`
4. Document it in this README

## License

MIT :  see [LICENSE](LICENSE).

---

Built by [Vishnu Kosuri](https://aresredteam.com) at ARES RED TEAM.
