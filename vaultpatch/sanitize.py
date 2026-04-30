"""Sanitize secrets by detecting and redacting sensitive patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Patterns that indicate a value is sensitive and should be flagged/redacted
_SENSITIVE_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "private_key_header": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "hex_secret": re.compile(r"^[0-9a-fA-F]{32,}$"),
}


@dataclass
class SanitizeMatch:
    path: str
    key: str
    pattern_name: str
    redacted_value: str

    def __repr__(self) -> str:
        return f"SanitizeMatch(path={self.path!r}, key={self.key!r}, pattern={self.pattern_name!r})"


@dataclass
class SanitizeReport:
    matches: List[SanitizeMatch] = field(default_factory=list)
    errors: Dict[str, str] = field(default_factory=dict)

    @property
    def flagged_count(self) -> int:
        return len(self.matches)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def summary(self) -> str:
        parts = [f"{self.flagged_count} sensitive value(s) flagged"]
        if self.error_count:
            parts.append(f"{self.error_count} error(s)")
        return ", ".join(parts)


def _redact(value: str) -> str:
    """Return a redacted representation of a value."""
    if len(value) <= 4:
        return "****"
    return value[:2] + "*" * (len(value) - 4) + value[-2:]


def _detect_pattern(value: str) -> Optional[str]:
    """Return the first matching pattern name, or None."""
    for name, pattern in _SENSITIVE_PATTERNS.items():
        if pattern.search(value):
            return name
    return None


def sanitize_secrets(
    client,
    paths: List[str],
) -> SanitizeReport:
    """Scan secrets at given paths and flag values matching sensitive patterns."""
    report = SanitizeReport()
    for path in paths:
        try:
            data = client.read_secret(path)
        except Exception as exc:  # noqa: BLE001
            report.errors[path] = str(exc)
            continue
        if not data:
            continue
        for key, value in data.items():
            if not isinstance(value, str):
                continue
            matched = _detect_pattern(value)
            if matched:
                report.matches.append(
                    SanitizeMatch(
                        path=path,
                        key=key,
                        pattern_name=matched,
                        redacted_value=_redact(value),
                    )
                )
    return report
