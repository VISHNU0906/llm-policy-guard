"""PII detection policy — identifies and redacts personally identifiable information."""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Any

from llm_policy_guard.models import (
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyViolation,
)

# PII patterns with labels
_PII_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "ssn",
        "US Social Security Number",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
    ),
    (
        "credit_card",
        "Credit Card Number",
        re.compile(
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|"
            r"6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11})\b"
        ),
    ),
    (
        "email",
        "Email Address",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone_us",
        "US Phone Number",
        re.compile(
            r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
        ),
    ),
    (
        "ipv4",
        "IPv4 Address",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        ),
    ),
    (
        "passport_us",
        "US Passport Number",
        re.compile(r"\b[A-Z]{1,2}[0-9]{6,9}\b"),
    ),
    (
        "dob",
        "Date of Birth Pattern",
        re.compile(
            r"\b(?:DOB|D\.O\.B|date\s+of\s+birth)\s*[:\-]?\s*\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "iban",
        "IBAN Bank Account",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b"),
    ),
]

_REDACT_CHAR = "*"


class PIIPolicy:
    """Detects and optionally redacts PII from LLM input/output."""

    def __init__(
        self,
        patterns: list[str] | None = None,
        action: PolicyAction = PolicyAction.REDACT,
        direction: ContentDirection = ContentDirection.BOTH,
    ) -> None:
        self.action = action
        self.direction = direction

        if patterns:
            self._active = [(k, label, pat) for k, label, pat in _PII_PATTERNS if k in patterns]
        else:
            self._active = _PII_PATTERNS

    def check(self, text: str, direction: ContentDirection) -> tuple[str, list[PolicyViolation]]:
        if not self._applies(direction):
            return text, []

        violations: list[PolicyViolation] = []
        result = text

        for key, label, pattern in self._active:
            matches = list(pattern.finditer(result))
            if not matches:
                continue

            for match in matches:
                matched = match.group(0)
                violations.append(
                    PolicyViolation(
                        rule_id=f"pii.{key}",
                        rule_name=f"PII: {label}",
                        category=PolicyCategory.PII,
                        severity="high",
                        action=self.action,
                        direction=direction,
                        matched_text=matched[:20] + "..." if len(matched) > 20 else matched,
                        message=f"Detected {label} in {direction.value}",
                        metadata={"pii_type": key, "match_length": len(matched)},
                    )
                )

            if self.action == PolicyAction.REDACT:
                result = pattern.sub(
                    lambda m: f"[{label.upper().replace(' ', '_')} REDACTED]",
                    result,
                )

        return result, violations

    def _applies(self, direction: ContentDirection) -> bool:
        return self.direction == ContentDirection.BOTH or self.direction == direction

    @staticmethod
    def redact(text: str, patterns: list[str] | None = None) -> str:
        """Convenience: redact PII and return the sanitized text."""
        policy = PIIPolicy(patterns=patterns, action=PolicyAction.REDACT)
        sanitized, _ = policy.check(text, ContentDirection.BOTH)
        return sanitized
