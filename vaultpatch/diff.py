"""Diff utilities for comparing old and new secret payloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SecretDiff:
    """Represents the diff between two versions of a secret."""

    path: str
    added: dict[str, Any] = field(default_factory=dict)
    removed: dict[str, Any] = field(default_factory=dict)
    changed: dict[str, tuple[Any, Any]] = field(default_factory=dict)
    unchanged: dict[str, Any] = field(default_factory=dict)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def summary(self) -> str:
        lines = [f"--- {self.path}"]
        for key, value in self.removed.items():
            lines.append(f"  - {key}: {_mask(value)}")
        for key, (old, new) in self.changed.items():
            lines.append(f"  ~ {key}: {_mask(old)} -> {_mask(new)}")
        for key, value in self.added.items():
            lines.append(f"  + {key}: {_mask(value)}")
        if not self.has_changes:
            lines.append("  (no changes)")
        return "\n".join(lines)


def _mask(value: Any, visible: int = 4) -> str:
    """Partially mask a secret value for safe display."""
    text = str(value)
    if len(text) <= visible:
        return "*" * len(text)
    return text[:visible] + "*" * (len(text) - visible)


def compute_diff(
    path: str,
    old: dict[str, Any],
    new: dict[str, Any],
) -> SecretDiff:
    """Compute the diff between *old* and *new* secret dicts."""
    diff = SecretDiff(path=path)
    all_keys = set(old) | set(new)
    for key in all_keys:
        if key not in old:
            diff.added[key] = new[key]
        elif key not in new:
            diff.removed[key] = old[key]
        elif old[key] != new[key]:
            diff.changed[key] = (old[key], new[key])
        else:
            diff.unchanged[key] = old[key]
    return diff
