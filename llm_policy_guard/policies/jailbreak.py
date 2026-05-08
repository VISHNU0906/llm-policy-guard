"""Jailbreak detection policy — catches prompt injection and safety bypass attempts."""

from __future__ import annotations

import re

from llm_policy_guard.models import (
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyViolation,
)

_JAILBREAK_PATTERNS: list[tuple[str, str, re.Pattern[str], str]] = [
    (
        "dan_mode",
        "DAN / Jailbreak Activation",
        re.compile(r"(?i)\bDAN\b.*\b(mode|prompt|jailbreak|activated)\b"),
        "critical",
    ),
    (
        "ignore_instructions",
        "Instruction Override",
        re.compile(
            r"(?i)(ignore|disregard|forget|override|bypass)\s+(all\s+)?"
            r"(previous|prior|above|system|original)\s+(instructions?|prompts?|rules?|constraints?|guidelines?)"
        ),
        "critical",
    ),
    (
        "role_override",
        "Role/Persona Override",
        re.compile(
            r"(?i)(you\s+are\s+now|pretend\s+you\s+are|act\s+as|roleplay\s+as)\s+"
            r"(a\s+)?(jailbroken|free|uncensored|unfiltered|unrestricted|evil|malicious)"
        ),
        "critical",
    ),
    (
        "dev_mode",
        "Developer/God Mode",
        re.compile(
            r"(?i)(developer|god|admin|root|debug|maintenance|test|sudo)\s+mode\s*(activated|enabled|on|:)"
        ),
        "high",
    ),
    (
        "hypothetical_frame",
        "Hypothetical Framing for Safety Bypass",
        re.compile(
            r"(?i)hypothetically\s+(speaking|,)?\s+(how\s+(would|could|do)\s+(?:one|you|I|someone))\s+"
            r"(make|create|build|synthesize|hack|exploit|bypass)"
        ),
        "high",
    ),
    (
        "fictional_frame",
        "Fictional Framing for Safety Bypass",
        re.compile(
            r"(?i)(in\s+(a\s+)?fiction|for\s+(a\s+)?story|write\s+(a\s+)?scene\s+where)\s+"
            r".{0,50}(instructions?|how\s+to|steps?\s+to|guide\s+(to|for))"
        ),
        "medium",
    ),
    (
        "control_token",
        "LLM Control Token Injection",
        re.compile(r"<\s*(system|im_start|im_end|s|assistant|user|human)\s*>|\[INST\]|\[/INST\]"),
        "critical",
    ),
    (
        "system_prompt_extract",
        "System Prompt Extraction",
        re.compile(
            r"(?i)(print|reveal|show|tell\s+me|output|repeat|what\s+is)\s+(your\s+)?"
            r"(system\s+prompt|initial\s+prompt|hidden\s+(instructions?|rules?|context))"
        ),
        "high",
    ),
    (
        "many_shot",
        "Many-Shot Jailbreak Attempt",
        re.compile(
            r"(?i)(user|human)\s*:\s*.*\n\s*(assistant|AI|model)\s*:\s*.*\n"
            r"(\s*(user|human)\s*:\s*.*\n\s*(assistant|AI|model)\s*:\s*.*\n){4,}"
        ),
        "medium",
    ),
]


class JailbreakPolicy:
    """Detects jailbreak attempts and prompt injection in LLM inputs."""

    def __init__(
        self,
        patterns: list[str] | None = None,
        action: PolicyAction = PolicyAction.BLOCK,
        direction: ContentDirection = ContentDirection.INPUT,
    ) -> None:
        self.action = action
        self.direction = direction

        if patterns:
            self._active = [(k, l, p, s) for k, l, p, s in _JAILBREAK_PATTERNS if k in patterns]
        else:
            self._active = _JAILBREAK_PATTERNS

    def check(self, text: str, direction: ContentDirection) -> tuple[str, list[PolicyViolation]]:
        if not self._applies(direction):
            return text, []

        violations: list[PolicyViolation] = []

        for key, label, pattern, severity in self._active:
            match = pattern.search(text)
            if match:
                violations.append(
                    PolicyViolation(
                        rule_id=f"jailbreak.{key}",
                        rule_name=f"Jailbreak: {label}",
                        category=PolicyCategory.JAILBREAK,
                        severity=severity,
                        action=self.action,
                        direction=direction,
                        matched_text=match.group(0)[:100],
                        message=f"Jailbreak pattern '{label}' detected in {direction.value}",
                        metadata={"pattern_id": key},
                    )
                )

        return text, violations  # Jailbreak policy blocks, doesn't redact

    def _applies(self, direction: ContentDirection) -> bool:
        return self.direction == ContentDirection.BOTH or self.direction == direction
