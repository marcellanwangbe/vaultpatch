"""Secret quality scoring for Vault paths."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class ScoreBreakdown:
    length_score: int = 0
    entropy_score: int = 0
    variety_score: int = 0
    penalty: int = 0

    @property
    def total(self) -> int:
        return max(0, self.length_score + self.entropy_score + self.variety_score - self.penalty)


@dataclass
class SecretScore:
    path: str
    key: str
    score: int
    grade: str
    breakdown: ScoreBreakdown
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def __repr__(self) -> str:
        return f"<SecretScore {self.path}:{self.key} grade={self.grade} score={self.score}>"


@dataclass
class ScoreReport:
    results: List[SecretScore] = field(default_factory=list)

    @property
    def average_score(self) -> float:
        valid = [r.score for r in self.results if r.ok]
        return round(sum(valid) / len(valid), 2) if valid else 0.0

    def summary(self) -> str:
        grades = {r.grade for r in self.results if r.ok}
        return (
            f"{len(self.results)} key(s) scored, "
            f"avg={self.average_score}, grades={sorted(grades)}"
        )


def _shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    freq = {c: value.count(c) / len(value) for c in set(value)}
    return -sum(p * math.log2(p) for p in freq.values())


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 55:
        return "C"
    if score >= 35:
        return "D"
    return "F"


def score_value(key: str, value: str) -> SecretScore:
    bd = ScoreBreakdown()
    length = len(value)
    bd.length_score = min(40, length * 2)
    entropy = _shannon_entropy(value)
    bd.entropy_score = min(40, int(entropy * 10))
    has_upper = bool(re.search(r"[A-Z]", value))
    has_digit = bool(re.search(r"[0-9]", value))
    has_special = bool(re.search(r"[^A-Za-z0-9]", value))
    bd.variety_score = sum([has_upper, has_digit, has_special]) * 7
    if re.fullmatch(r"[a-z]+", value):
        bd.penalty += 10
    if value.lower() in {"password", "secret", "changeme", "admin", "test"}:
        bd.penalty += 30
    score = bd.total
    return SecretScore(
        path="", key=key, score=score, grade=_grade(score), breakdown=bd
    )


def score_path(
    client: VaultClient,
    path: str,
    keys: Optional[List[str]] = None,
) -> List[SecretScore]:
    data, err = client.read_secret(path)
    if err:
        return [SecretScore(path=path, key="*", score=0, grade="F",
                            breakdown=ScoreBreakdown(), error=err)]
    results = []
    for k, v in (data or {}).items():
        if keys and k not in keys:
            continue
        s = score_value(k, str(v))
        s.path = path
        results.append(s)
    return results


def score_paths(
    client: VaultClient,
    paths: List[str],
    keys: Optional[List[str]] = None,
) -> ScoreReport:
    report = ScoreReport()
    for path in paths:
        report.results.extend(score_path(client, path, keys))
    return report
