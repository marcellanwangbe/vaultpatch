"""Redact sensitive keys from Vault secret paths before display or export."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional
import re

# Default patterns considered sensitive
DEFAULT_SENSITIVE_PATTERNS: List[str] = [
    r"(?i)password",
    r"(?i)secret",
    r"(?i)token",
    r"(?i)api[_-]?key",
    r"(?i)private[_-]?key",
    r"(?i)credential",
]

REDACTED_PLACEHOLDER = "**REDACTED**"


@dataclass
class RedactResult:
    path: str
    original: Dict[str, str]
    redacted: Dict[str, str]
    redacted_keys: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return True

    def __repr__(self) -> str:
        return (
            f"RedactResult(path={self.path!r}, "
            f"redacted_keys={self.redacted_keys})"
        )


@dataclass
class RedactReport:
    results: List[RedactResult] = field(default_factory=list)

    @property
    def total_redacted_keys(self) -> int:
        return sum(len(r.redacted_keys) for r in self.results)

    def summary(self) -> str:
        return (
            f"Redacted {self.total_redacted_keys} key(s) "
            f"across {len(self.results)} path(s)."
        )


def _is_sensitive(key: str, patterns: List[str]) -> bool:
    return any(re.search(p, key) for p in patterns)


def redact_secrets(
    client,
    paths: List[str],
    extra_patterns: Optional[List[str]] = None,
    placeholder: str = REDACTED_PLACEHOLDER,
) -> RedactReport:
    """Read secrets at each path and return copies with sensitive values replaced."""
    patterns = DEFAULT_SENSITIVE_PATTERNS + (extra_patterns or [])
    report = RedactReport()

    for path in paths:
        data = client.read_secret(path) or {}
        redacted: Dict[str, str] = {}
        redacted_keys: List[str] = []

        for key, value in data.items():
            if _is_sensitive(key, patterns):
                redacted[key] = placeholder
                redacted_keys.append(key)
            else:
                redacted[key] = value

        report.results.append(
            RedactResult(
                path=path,
                original=dict(data),
                redacted=redacted,
                redacted_keys=redacted_keys,
            )
        )

    return report
