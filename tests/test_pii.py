"""Tests for PII detection and redaction."""

import pytest

from llm_policy_guard.models import ContentDirection, PolicyAction, PolicyViolation
from llm_policy_guard.policies.pii import PIIPolicy


@pytest.fixture
def pii() -> PIIPolicy:
    return PIIPolicy(action=PolicyAction.REDACT)


class TestPIIDetection:
    def test_ssn_detected(self, pii):
        text = "My SSN is 123-45-6789"
        _, violations = pii.check(text, ContentDirection.INPUT)
        assert any(v.rule_id == "pii.ssn" for v in violations)

    def test_email_detected(self, pii):
        text = "Contact me at john.doe@example.com for more info"
        _, violations = pii.check(text, ContentDirection.INPUT)
        assert any(v.rule_id == "pii.email" for v in violations)

    def test_credit_card_detected(self, pii):
        text = "My card number is 4111111111111111"
        _, violations = pii.check(text, ContentDirection.INPUT)
        assert any(v.rule_id == "pii.credit_card" for v in violations)

    def test_clean_text_no_violations(self, pii):
        text = "This is a clean message about general topics."
        _, violations = pii.check(text, ContentDirection.INPUT)
        assert len(violations) == 0

    def test_multiple_pii_types(self, pii):
        text = "SSN: 123-45-6789, email: foo@bar.com"
        _, violations = pii.check(text, ContentDirection.INPUT)
        rule_ids = {v.rule_id for v in violations}
        assert "pii.ssn" in rule_ids
        assert "pii.email" in rule_ids


class TestPIIRedaction:
    def test_ssn_redacted(self, pii):
        text = "My SSN is 123-45-6789"
        result, _ = pii.check(text, ContentDirection.INPUT)
        assert "123-45-6789" not in result
        assert "REDACTED" in result

    def test_email_redacted(self, pii):
        text = "Email: test@example.com"
        result, _ = pii.check(text, ContentDirection.INPUT)
        assert "test@example.com" not in result

    def test_static_redact(self):
        text = "SSN: 123-45-6789 and email: foo@bar.com"
        result = PIIPolicy.redact(text)
        assert "123-45-6789" not in result
        assert "foo@bar.com" not in result


class TestDirectionFiltering:
    def test_input_only_policy_skips_output(self):
        pii = PIIPolicy(action=PolicyAction.REDACT, direction=ContentDirection.INPUT)
        text = "SSN: 123-45-6789"
        _, violations = pii.check(text, ContentDirection.OUTPUT)
        assert len(violations) == 0

    def test_output_only_policy_skips_input(self):
        pii = PIIPolicy(action=PolicyAction.REDACT, direction=ContentDirection.OUTPUT)
        text = "SSN: 123-45-6789"
        _, violations = pii.check(text, ContentDirection.INPUT)
        assert len(violations) == 0
