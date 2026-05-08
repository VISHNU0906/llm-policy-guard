"""YAML policy loader — parse policy files into PolicyConfig objects."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from llm_policy_guard.models import (
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyConfig,
    PolicyRule,
)


def load_policy(path: str | Path) -> PolicyConfig:
    """Load a YAML policy file and return a PolicyConfig."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    with p.open(encoding="utf-8") as f:
        data = yaml.safe_load(f)

    return _parse_config(data)


def load_policy_string(yaml_str: str) -> PolicyConfig:
    """Parse a YAML policy string."""
    data = yaml.safe_load(yaml_str)
    return _parse_config(data)


def _parse_config(data: dict[str, Any]) -> PolicyConfig:
    rules: list[PolicyRule] = []

    for i, rule_data in enumerate(data.get("rules", [])):
        rule = PolicyRule(
            id=rule_data.get("id", f"rule_{i}"),
            name=rule_data.get("name", f"Rule {i}"),
            category=PolicyCategory(rule_data.get("category", "custom")),
            description=rule_data.get("description", ""),
            enabled=rule_data.get("enabled", True),
            action=PolicyAction(rule_data.get("action", "block")),
            direction=ContentDirection(rule_data.get("direction", "both")),
            severity=rule_data.get("severity", "high"),
            config=rule_data.get("config", {}),
        )
        rules.append(rule)

    return PolicyConfig(
        name=data.get("name", "default"),
        version=str(data.get("version", "1.0")),
        description=data.get("description", ""),
        rules=rules,
        default_action=PolicyAction(data.get("default_action", "block")),
        audit_all=data.get("audit_all", False),
    )
