"""Audit logging — records all policy decisions for compliance and review."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from llm_policy_guard.models import AuditEntry, PolicyViolation

logger = logging.getLogger(__name__)


class AuditLog:
    """Append-only audit log for policy decisions."""

    def __init__(self, path: Path | str | None = None) -> None:
        self._path = Path(path) if path else None
        self._entries: list[AuditEntry] = []

    def record(self, entry: AuditEntry) -> None:
        self._entries.append(entry)
        if self._path:
            self._append_to_file(entry)
        logger.info(
            "policy_audit action=%s violations=%d direction=%s hash=%s",
            entry.action_taken.value,
            entry.violation_count,
            entry.direction.value,
            entry.content_hash,
        )

    def _append_to_file(self, entry: AuditEntry) -> None:
        try:
            with self._path.open("a", encoding="utf-8") as f:
                f.write(entry.model_dump_json() + "\n")
        except OSError as e:
            logger.warning("Failed to write audit log: %s", e)

    def entries(self, since: datetime | None = None) -> list[AuditEntry]:
        if since is None:
            return list(self._entries)
        return [e for e in self._entries if e.timestamp >= since]

    def violations_by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entry in self._entries:
            for v in entry.violations:
                counts[v.rule_id] = counts.get(v.rule_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda x: -x[1]))

    def summary(self) -> dict[str, Any]:
        total = len(self._entries)
        blocked = sum(1 for e in self._entries if not e.passed)
        violations: list[PolicyViolation] = []
        for e in self._entries:
            violations.extend(e.violations)

        return {
            "total_checks": total,
            "blocked": blocked,
            "passed": total - blocked,
            "block_rate": f"{blocked / total * 100:.1f}%" if total else "0%",
            "total_violations": len(violations),
            "top_rules": list(self.violations_by_rule().items())[:5],
        }

    @classmethod
    def from_file(cls, path: Path | str) -> "AuditLog":
        log = cls(path=path)
        p = Path(path)
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    try:
                        log._entries.append(AuditEntry.model_validate_json(line))
                    except Exception:
                        pass
        return log
