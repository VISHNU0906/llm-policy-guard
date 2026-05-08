"""Content policy — category-based content filtering."""

from __future__ import annotations

import re
from typing import Any

from llm_policy_guard.models import (
    ContentDirection,
    PolicyAction,
    PolicyCategory,
    PolicyViolation,
)

_BUILTIN_CATEGORIES: dict[str, dict[str, Any]] = {
    "weapons_of_mass_destruction": {
        "label": "WMD Content",
        "severity": "critical",
        "patterns": [
            r"(?i)(synthesis|manufacture|produce|create)\s+(nerve\s+agent|sarin|VX\s+gas|novichok|mustard\s+gas)",
            r"(?i)(enrich|weaponize)\s+(uranium|plutonium)",
            r"(?i)(dirty\s+bomb|radiological\s+weapon)",
        ],
    },
    "csam": {
        "label": "CSAM",
        "severity": "critical",
        "patterns": [
            r"(?i)child\s+(pornography|sexual\s+abuse\s+material|exploitation)",
            r"(?i)(sexual|explicit)\s+content\s+(featuring|involving|with)\s+(minor|child|underage)",
        ],
    },
    "hate_speech": {
        "label": "Hate Speech",
        "severity": "high",
        "patterns": [
            r"(?i)(kill|exterminate|genocide)\s+all\s+(jews|muslims|blacks|whites|asians|hispanics)",
            r"(?i)\[ethnic/racial slur\]\s+(should|deserve|must)\s+(die|be\s+killed|be\s+exterminated)",
        ],
    },
    "self_harm": {
        "label": "Self-Harm Instructions",
        "severity": "high",
        "patterns": [
            r"(?i)(step[- ]by[- ]step|how\s+to|instructions?\s+for)\s+(commit\s+)?suicide",
            r"(?i)(lethal|fatal)\s+dose\s+of\s+\w+\s+for\s+(a\s+)?(human|person|adult|child)",
        ],
    },
    "malware": {
        "label": "Malware / Cyberweapon",
        "severity": "high",
        "patterns": [
            r"(?i)(write|create|generate|code)\s+(a\s+)?(ransomware|keylogger|rootkit|botnet|worm|trojan)",
            r"(?i)C2\s+(server|infrastructure|beacon)\s+(code|implementation|setup)",
        ],
    },
}


class ContentPolicy:
    """Category-based content filter for LLM inputs and outputs."""

    def __init__(
        self,
        categories: list[str] | None = None,
        custom_patterns: list[dict[str, Any]] | None = None,
        action: PolicyAction = PolicyAction.BLOCK,
        direction: ContentDirection = ContentDirection.BOTH,
    ) -> None:
        self.action = action
        self.direction = direction

        # Build active category set
        active_cats = categories or list(_BUILTIN_CATEGORIES.keys())
        self._rules: list[tuple[str, str, str, list[re.Pattern[str]]]] = []

        for cat_id in active_cats:
            if cat_id in _BUILTIN_CATEGORIES:
                cat = _BUILTIN_CATEGORIES[cat_id]
                self._rules.append(
                    (
                        cat_id,
                        cat["label"],
                        cat["severity"],
                        [re.compile(p) for p in cat["patterns"]],
                    )
                )

        # Add custom patterns
        if custom_patterns:
            for cp in custom_patterns:
                self._rules.append(
                    (
                        cp.get("id", "custom"),
                        cp.get("label", "Custom Policy"),
                        cp.get("severity", "high"),
                        [re.compile(cp["pattern"])],
                    )
                )

    def check(self, text: str, direction: ContentDirection) -> tuple[str, list[PolicyViolation]]:
        if not self._applies(direction):
            return text, []

        violations: list[PolicyViolation] = []

        for cat_id, label, severity, patterns in self._rules:
            for pattern in patterns:
                match = pattern.search(text)
                if match:
                    violations.append(
                        PolicyViolation(
                            rule_id=f"content.{cat_id}",
                            rule_name=f"Content: {label}",
                            category=PolicyCategory.CONTENT,
                            severity=severity,
                            action=self.action,
                            direction=direction,
                            matched_text=match.group(0)[:100],
                            message=f"Content policy violation: {label} detected in {direction.value}",
                            metadata={"category": cat_id},
                        )
                    )
                    break  # One violation per category is enough

        return text, violations

    def _applies(self, direction: ContentDirection) -> bool:
        return self.direction == ContentDirection.BOTH or self.direction == direction
