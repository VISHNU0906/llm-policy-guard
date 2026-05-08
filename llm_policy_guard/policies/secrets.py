"""Secrets detection policy — finds API keys, tokens, and credentials."""

from __future__ import annotations

import re

from llm_policy_guard.models import (
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyViolation,
)

# Secret patterns: (id, label, pattern, min_length)
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern[str], int]] = [
    (
        "openai_key",
        "OpenAI API Key",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9]{20,}\b"),
        30,
    ),
    (
        "anthropic_key",
        "Anthropic API Key",
        re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{90,}\b"),
        95,
    ),
    (
        "aws_access_key",
        "AWS Access Key ID",
        re.compile(r"\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
        20,
    ),
    (
        "aws_secret_key",
        "AWS Secret Access Key",
        re.compile(r"\b[A-Za-z0-9+/]{40}\b"),
        40,
    ),
    (
        "github_token",
        "GitHub Personal Access Token",
        re.compile(r"\b(?:ghp|ghs|gho|ghr|ghu)_[A-Za-z0-9_]{36,}\b"),
        40,
    ),
    (
        "jwt",
        "JSON Web Token",
        re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
        50,
    ),
    (
        "gcp_service_account",
        "GCP Service Account Key",
        re.compile(r'"private_key"\s*:\s*"-----BEGIN RSA PRIVATE KEY-----'),
        40,
    ),
    (
        "private_key_pem",
        "PEM Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        40,
    ),
    (
        "password_in_url",
        "Password in URL",
        re.compile(r"https?://[^:@\s]+:[^@\s]{8,}@[^\s]+"),
        20,
    ),
    (
        "bearer_token",
        "Bearer Token",
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-_\.~\+\/]{20,}={0,2}\b"),
        30,
    ),
    (
        "generic_secret",
        "Generic Secret Assignment",
        re.compile(
            r"(?i)(?:password|passwd|secret|api_key|apikey|auth_token|access_token)\s*[=:]\s*['\"]?([A-Za-z0-9!@#$%^&*()_+\-=]{12,})['\"]?"
        ),
        12,
    ),
]

_ENTROPY_THRESHOLD = 4.0  # Shannon entropy threshold for high-entropy string detection


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {c: s.count(c) / len(s) for c in set(s)}
    return -sum(p * math.log2(p) for p in freq.values())


class SecretsPolicy:
    """Detects secrets, credentials, and API keys in LLM input/output."""

    def __init__(
        self,
        patterns: list[str] | None = None,
        action: PolicyAction = PolicyAction.BLOCK,
        direction: ContentDirection = ContentDirection.BOTH,
        entropy_check: bool = True,
    ) -> None:
        self.action = action
        self.direction = direction
        self.entropy_check = entropy_check

        if patterns:
            self._active = [(k, l, p, m) for k, l, p, m in _SECRET_PATTERNS if k in patterns]
        else:
            self._active = _SECRET_PATTERNS

    def check(self, text: str, direction: ContentDirection) -> tuple[str, list[PolicyViolation]]:
        if not self._applies(direction):
            return text, []

        violations: list[PolicyViolation] = []
        result = text

        for key, label, pattern, min_len in self._active:
            for match in pattern.finditer(result):
                matched = match.group(0)
                if len(matched) < min_len:
                    continue

                # Entropy check for generic patterns
                if self.entropy_check and key == "generic_secret":
                    value_match = match.group(1) if match.lastindex else matched
                    if _shannon_entropy(value_match) < _ENTROPY_THRESHOLD:
                        continue

                violations.append(
                    PolicyViolation(
                        rule_id=f"secrets.{key}",
                        rule_name=f"Secret: {label}",
                        category=PolicyCategory.SECRETS,
                        severity="critical",
                        action=self.action,
                        direction=direction,
                        matched_text=matched[:8] + "..." + matched[-4:] if len(matched) > 12 else "[redacted]",
                        message=f"Detected {label} in {direction.value}",
                        metadata={"secret_type": key, "match_length": len(matched)},
                    )
                )

                if self.action == PolicyAction.REDACT:
                    result = result.replace(matched, f"[{label.upper().replace(' ', '_')} REDACTED]", 1)

        return result, violations

    def _applies(self, direction: ContentDirection) -> bool:
        return self.direction == ContentDirection.BOTH or self.direction == direction
