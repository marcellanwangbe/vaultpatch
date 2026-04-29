"""Audit log module for recording secret rotation events."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from vaultpatch.rotator import RotationResult


@dataclass
class AuditEntry:
    """A single audit log entry for a rotation event."""

    timestamp: str
    path: str
    namespace: Optional[str]
    changed_keys: List[str]
    added_keys: List[str]
    removed_keys: List[str]
    dry_run: bool
    success: bool
    error: Optional[str] = None

    @classmethod
    def from_rotation_result(cls, result: RotationResult, dry_run: bool = False) -> "AuditEntry":
        diff = result.diff
        return cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            path=result.path,
            namespace=result.namespace,
            changed_keys=list(diff.changed.keys()),
            added_keys=list(diff.added.keys()),
            removed_keys=list(diff.removed.keys()),
            dry_run=dry_run,
            success=result.success,
            error=result.error,
        )

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLogger:
    """Appends JSON-lines audit entries to a log file."""

    def __init__(self, log_path: str | os.PathLike) -> None:
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def record(self, entry: AuditEntry) -> None:
        """Append a single audit entry as a JSON line."""
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry.to_dict()) + "\n")

    def record_result(self, result: RotationResult, dry_run: bool = False) -> AuditEntry:
        """Build an AuditEntry from a RotationResult and persist it."""
        entry = AuditEntry.from_rotation_result(result, dry_run=dry_run)
        self.record(entry)
        return entry

    def read_all(self) -> List[AuditEntry]:
        """Return all entries from the log file."""
        if not self.log_path.exists():
            return []
        entries: List[AuditEntry] = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    data = json.loads(line)
                    entries.append(AuditEntry(**data))
        return entries
