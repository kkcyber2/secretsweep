"""Finding model."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def redact(value: str, keep: int = 4) -> str:
    """Mask a secret, keeping only a short prefix so it can be identified."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * min(24, len(value) - keep)


@dataclass
class Finding:
    rule: str
    description: str
    severity: Severity
    path: str
    line: int
    column: int
    match: str
    entropy: float | None = None

    def public(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "description": self.description,
            "severity": self.severity.value,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "match": redact(self.match),
            "entropy": round(self.entropy, 3) if self.entropy is not None else None,
        }
