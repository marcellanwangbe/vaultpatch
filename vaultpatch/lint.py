"""Lint secrets at given Vault paths against configurable rules."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient


@dataclass
class LintViolation:
    path: str
    key: str
    rule: str
    message: str

    def __str__(self) -> str:
        return f"[{self.path}] {self.key}: {self.rule} — {self.message}"


@dataclass
class LintResult:
    path: str
    violations: List[LintViolation] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and len(self.violations) == 0

    def summary(self) -> str:
        if self.error:
            return f"{self.path}: ERROR — {self.error}"
        if self.ok:
            return f"{self.path}: OK"
        return f"{self.path}: {len(self.violations)} violation(s)"


@dataclass
class LintReport:
    results: List[LintResult] = field(default_factory=list)

    @property
    def violation_count(self) -> int:
        return sum(len(r.violations) for r in self.results)

    @property
    def error_count(self) -> int:
        return sum(1 for r in self.results if r.error)

    def summary(self) -> str:
        total = len(self.results)
        return (
            f"{total} path(s) checked, "
            f"{self.violation_count} violation(s), "
            f"{self.error_count} error(s)"
        )


_RULES = {
    "no_empty_value": (lambda v: v != "", "Value must not be empty"),
    "min_length_8": (lambda v: len(v) >= 8, "Value must be at least 8 characters"),
    "has_uppercase": (lambda v: any(c.isupper() for c in v), "Value must contain an uppercase letter"),
    "has_digit": (lambda v: any(c.isdigit() for c in v), "Value must contain a digit"),
    "no_whitespace": (lambda v: not re.search(r"\s", v), "Value must not contain whitespace"),
}


def lint_path(
    client: VaultClient,
    path: str,
    rules: Optional[List[str]] = None,
    forbidden_keys: Optional[List[str]] = None,
) -> LintResult:
    active_rules = rules or list(_RULES.keys())
    forbidden = [k.lower() for k in (forbidden_keys or [])]

    try:
        data = client.read_secret(path)
    except Exception as exc:
        return LintResult(path=path, error=str(exc))

    violations: List[LintViolation] = []
    for key, value in data.items():
        if key.lower() in forbidden:
            violations.append(
                LintViolation(path, key, "forbidden_key", f"Key '{key}' is not allowed")
            )
            continue
        for rule_name in active_rules:
            checker, message = _RULES.get(rule_name, (None, None))
            if checker and not checker(str(value)):
                violations.append(LintViolation(path, key, rule_name, message))

    return LintResult(path=path, violations=violations)


def lint_paths(
    client: VaultClient,
    paths: List[str],
    rules: Optional[List[str]] = None,
    forbidden_keys: Optional[List[str]] = None,
) -> LintReport:
    results = [
        lint_path(client, p, rules=rules, forbidden_keys=forbidden_keys)
        for p in paths
    ]
    return LintReport(results=results)
