"""Policy validation for Vault secrets rotation."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class PolicyViolation:
    path: str
    key: str
    reason: str

    def __str__(self) -> str:
        return f"[{self.path}] {self.key}: {self.reason}"


@dataclass
class PolicyResult:
    violations: List[PolicyViolation] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return len(self.violations) == 0

    def summary(self) -> str:
        if self.passed:
            return "Policy check passed — no violations found."
        lines = [f"Policy check failed with {len(self.violations)} violation(s):"]
        for v in self.violations:
            lines.append(f"  - {v}")
        return "\n".join(lines)


@dataclass
class SecretPolicy:
    """Defines rules that new secret values must satisfy."""
    min_length: int = 8
    require_uppercase: bool = False
    require_digit: bool = False
    forbidden_keys: List[str] = field(default_factory=list)
    key_pattern: Optional[str] = None  # regex keys must match

    def validate(self, path: str, secrets: dict) -> PolicyResult:
        result = PolicyResult()
        compiled = re.compile(self.key_pattern) if self.key_pattern else None

        for key, value in secrets.items():
            if key in self.forbidden_keys:
                result.violations.append(
                    PolicyViolation(path, key, "key is forbidden by policy")
                )
                continue

            if compiled and not compiled.match(key):
                result.violations.append(
                    PolicyViolation(path, key, f"key does not match pattern '{self.key_pattern}'")
                )

            str_val = str(value)
            if len(str_val) < self.min_length:
                result.violations.append(
                    PolicyViolation(path, key, f"value too short (min {self.min_length} chars)")
                )
            if self.require_uppercase and not any(c.isupper() for c in str_val):
                result.violations.append(
                    PolicyViolation(path, key, "value must contain at least one uppercase letter")
                )
            if self.require_digit and not any(c.isdigit() for c in str_val):
                result.violations.append(
                    PolicyViolation(path, key, "value must contain at least one digit")
                )

        return result
