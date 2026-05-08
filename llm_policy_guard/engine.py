"""Policy engine — applies all active policies to LLM input/output."""

from __future__ import annotations

import hashlib
import logging
from typing import Any

from llm_policy_guard.audit import AuditLog
from llm_policy_guard.models import (
    AuditEntry,
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyConfig,
    PolicyViolation,
)
from llm_policy_guard.policies.content import ContentPolicy
from llm_policy_guard.policies.jailbreak import JailbreakPolicy
from llm_policy_guard.policies.pii import PIIPolicy
from llm_policy_guard.policies.secrets import SecretsPolicy

logger = logging.getLogger(__name__)


class PolicyBlockedError(Exception):
    """Raised when a policy blocks content."""

    def __init__(self, violations: list[PolicyViolation]) -> None:
        self.violations = violations
        rules = ", ".join(v.rule_name for v in violations[:3])
        super().__init__(f"Content blocked by policy rules: {rules}")


class PolicyViolation(PolicyViolation):  # type: ignore[no-redef]
    pass


# Re-export for import convenience
from llm_policy_guard.models import PolicyViolation  # noqa: E402, F811


class PolicyEngine:
    """
    Main entry point — applies all configured policies to content.

    Usage::

        engine = PolicyEngine.from_config(policy_config)
        try:
            clean_text = engine.check_input(user_message)
        except PolicyBlockedError as e:
            return {"error": "blocked", "violations": [v.model_dump() for v in e.violations]}

        response = llm.complete(clean_text)

        try:
            safe_response = engine.check_output(response)
        except PolicyBlockedError as e:
            return {"error": "output_blocked"}
    """

    def __init__(
        self,
        config: PolicyConfig,
        audit_log: AuditLog | None = None,
        raise_on_block: bool = True,
    ) -> None:
        self.config = config
        self.audit_log = audit_log
        self.raise_on_block = raise_on_block
        self._checkers: list[Any] = self._build_checkers()

    @classmethod
    def from_config(cls, config: PolicyConfig, **kwargs: Any) -> "PolicyEngine":
        return cls(config, **kwargs)

    def check_input(self, text: str, session_id: str | None = None) -> str:
        return self._check(text, ContentDirection.INPUT, session_id)

    def check_output(self, text: str, session_id: str | None = None) -> str:
        return self._check(text, ContentDirection.OUTPUT, session_id)

    def check(self, text: str, direction: ContentDirection, session_id: str | None = None) -> str:
        return self._check(text, direction, session_id)

    def _check(self, text: str, direction: ContentDirection, session_id: str | None) -> str:
        all_violations: list[PolicyViolation] = []
        current_text = text

        for checker in self._checkers:
            try:
                current_text, violations = checker.check(current_text, direction)
                all_violations.extend(violations)
            except Exception as e:
                logger.warning("Policy checker %s failed: %s", type(checker).__name__, e)

        # Determine final action
        action = self._final_action(all_violations)

        # Audit
        if self.audit_log and (all_violations or self.config.audit_all):
            entry = AuditEntry(
                session_id=session_id,
                direction=direction,
                content_hash=hashlib.sha256(text.encode()).hexdigest()[:16],
                content_length=len(text),
                violations=all_violations,
                action_taken=action,
                passed=not bool(all_violations),
            )
            self.audit_log.record(entry)

        if all_violations and action == PolicyAction.BLOCK and self.raise_on_block:
            block_violations = [v for v in all_violations if v.action == PolicyAction.BLOCK]
            if block_violations:
                raise PolicyBlockedError(block_violations)

        return current_text

    def _final_action(self, violations: list[PolicyViolation]) -> PolicyAction:
        if not violations:
            return PolicyAction.LOG

        action_priority = {
            PolicyAction.BLOCK: 0,
            PolicyAction.REDACT: 1,
            PolicyAction.FLAG: 2,
            PolicyAction.LOG: 3,
        }
        return min(violations, key=lambda v: action_priority[v.action]).action

    def _build_checkers(self) -> list[Any]:
        checkers: list[Any] = []

        for rule in self.config.enabled_rules:
            category = rule.category
            cfg = rule.config

            if category == PolicyCategory.PII:
                checkers.append(
                    PIIPolicy(
                        patterns=cfg.get("patterns"),
                        action=rule.action,
                        direction=rule.direction,
                    )
                )
            elif category == PolicyCategory.SECRETS:
                checkers.append(
                    SecretsPolicy(
                        patterns=cfg.get("patterns"),
                        action=rule.action,
                        direction=rule.direction,
                        entropy_check=cfg.get("entropy_check", True),
                    )
                )
            elif category == PolicyCategory.JAILBREAK:
                checkers.append(
                    JailbreakPolicy(
                        patterns=cfg.get("patterns"),
                        action=rule.action,
                        direction=rule.direction,
                    )
                )
            elif category == PolicyCategory.CONTENT:
                checkers.append(
                    ContentPolicy(
                        categories=cfg.get("categories"),
                        custom_patterns=cfg.get("custom_patterns"),
                        action=rule.action,
                        direction=rule.direction,
                    )
                )

        return checkers

    @property
    def rule_count(self) -> int:
        return len(self.config.enabled_rules)
