"""Verify that secrets at given paths match expected values or patterns."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class VerifyResult:
    path: str
    key: str
    passed: bool
    reason: str = ""

    def ok(self) -> bool:
        return self.passed

    def __repr__(self) -> str:  # pragma: no cover
        status = "PASS" if self.passed else "FAIL"
        return f"VerifyResult({status} {self.path}#{self.key}: {self.reason})"


@dataclass
class VerifyReport:
    results: List[VerifyResult] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.passed)

    def all_passed(self) -> bool:
        return self.failed_count == 0

    def summary(self) -> str:
        return (
            f"verify: {self.passed_count} passed, {self.failed_count} failed "
            f"out of {len(self.results)} checks"
        )


def verify_secrets(
    client: VaultClient,
    path: str,
    expectations: Dict[str, str],
    *,
    use_regex: bool = False,
) -> VerifyReport:
    """Check that each key in *expectations* matches the live secret value.

    Args:
        client: authenticated VaultClient.
        path: secret path to read.
        expectations: mapping of key -> expected value (or regex pattern).
        use_regex: when True, treat expected values as regex patterns.

    Returns:
        VerifyReport containing one VerifyResult per key checked.
    """
    report = VerifyReport()

    try:
        data: Optional[Dict[str, str]] = client.read_secret(path)
    except Exception as exc:  # noqa: BLE001
        for key in expectations:
            report.results.append(
                VerifyResult(path=path, key=key, passed=False, reason=f"read error: {exc}")
            )
        return report

    if data is None:
        for key in expectations:
            report.results.append(
                VerifyResult(path=path, key=key, passed=False, reason="path not found")
            )
        return report

    for key, expected in expectations.items():
        if key not in data:
            report.results.append(
                VerifyResult(path=path, key=key, passed=False, reason="key missing")
            )
            continue

        actual = data[key]
        if use_regex:
            matched = bool(re.search(expected, actual))
            reason = "regex matched" if matched else f"regex {expected!r} did not match"
        else:
            matched = actual == expected
            reason = "exact match" if matched else "value mismatch"

        report.results.append(
            VerifyResult(path=path, key=key, passed=matched, reason=reason)
        )

    return report
