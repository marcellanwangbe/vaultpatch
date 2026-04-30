"""Secret path locking — prevent concurrent rotation of the same paths."""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

_DEFAULT_LOCK_DIR = Path.home() / ".vaultpatch" / "locks"


@dataclass
class LockEntry:
    path: str
    pid: int
    acquired_at: float
    ttl: float  # seconds

    def is_expired(self) -> bool:
        return (time.time() - self.acquired_at) > self.ttl

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "pid": self.pid,
            "acquired_at": self.acquired_at,
            "ttl": self.ttl,
        }

    @staticmethod
    def from_dict(data: dict) -> "LockEntry":
        return LockEntry(
            path=data["path"],
            pid=data["pid"],
            acquired_at=data["acquired_at"],
            ttl=data["ttl"],
        )


@dataclass
class LockManager:
    lock_dir: Path = field(default_factory=lambda: _DEFAULT_LOCK_DIR)
    ttl: float = 300.0

    def _lock_file(self, path: str) -> Path:
        safe = path.replace("/", "__").strip("_")
        return self.lock_dir / f"{safe}.lock"

    def acquire(self, path: str) -> bool:
        """Try to acquire a lock. Returns True on success, False if already locked."""
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        lf = self._lock_file(path)
        if lf.exists():
            entry = LockEntry.from_dict(json.loads(lf.read_text()))
            if not entry.is_expired():
                return False
        entry = LockEntry(path=path, pid=os.getpid(), acquired_at=time.time(), ttl=self.ttl)
        lf.write_text(json.dumps(entry.to_dict()))
        return True

    def release(self, path: str) -> None:
        lf = self._lock_file(path)
        if lf.exists():
            lf.unlink()

    def is_locked(self, path: str) -> bool:
        lf = self._lock_file(path)
        if not lf.exists():
            return False
        entry = LockEntry.from_dict(json.loads(lf.read_text()))
        return not entry.is_expired()

    def list_locks(self) -> List[LockEntry]:
        if not self.lock_dir.exists():
            return []
        entries = []
        for lf in self.lock_dir.glob("*.lock"):
            try:
                entry = LockEntry.from_dict(json.loads(lf.read_text()))
                if not entry.is_expired():
                    entries.append(entry)
            except Exception:
                pass
        return entries

    def clear_expired(self) -> int:
        if not self.lock_dir.exists():
            return 0
        removed = 0
        for lf in self.lock_dir.glob("*.lock"):
            try:
                entry = LockEntry.from_dict(json.loads(lf.read_text()))
                if entry.is_expired():
                    lf.unlink()
                    removed += 1
            except Exception:
                lf.unlink()
                removed += 1
        return removed
