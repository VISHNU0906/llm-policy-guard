"""Core data models for policy definitions and violations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class PolicyAction(str, Enum):
    BLOCK = "block"
    REDACT = "redact"
    FLAG = "flag"
    LOG = "log"


class PolicyCategory(str, Enum):
    PII = "pii"
    SECRETS = "secrets"
    JAILBREAK = "jailbreak"
    CONTENT = "content"
    CUSTOM = "custom"


class ContentDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    BOTH = "both"


class PolicyRule(BaseModel):
    id: str
    name: str
    category: PolicyCategory
    description: str = ""
    enabled: bool = True
    action: PolicyAction = PolicyAction.BLOCK
    direction: ContentDirection = ContentDirection.BOTH
    severity: Literal["critical", "high", "medium", "low"] = "high"

    # Rule-specific config (overlaid by subclasses)
    config: dict[str, Any] = Field(default_factory=dict)


class PolicyConfig(BaseModel):
    name: str
    version: str = "1.0"
    description: str = ""
    rules: list[PolicyRule] = Field(default_factory=list)
    default_action: PolicyAction = PolicyAction.BLOCK
    audit_all: bool = False

    @property
    def enabled_rules(self) -> list[PolicyRule]:
        return [r for r in self.rules if r.enabled]


class PolicyViolation(BaseModel):
    rule_id: str
    rule_name: str
    category: PolicyCategory
    severity: str
    action: PolicyAction
    direction: ContentDirection
    matched_text: str | None = None
    redacted_text: str | None = None
    message: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEntry(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    session_id: str | None = None
    direction: ContentDirection
    content_hash: str
    content_length: int
    violations: list[PolicyViolation] = Field(default_factory=list)
    action_taken: PolicyAction
    passed: bool

    @property
    def violation_count(self) -> int:
        return len(self.violations)
