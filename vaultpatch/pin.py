"""Pin module: record and enforce expected secret versions at Vault paths."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class PinEntry:
    path: str
    fingerprint: str  # SHA-256 of sorted JSON-encoded secret data
    version: Optional[int] = None

    def to_dict(self) -> dict:
        return {"path": self.path, "fingerprint": self.fingerprint, "version": self.version}

    @staticmethod
    def from_dict(d: dict) -> "PinEntry":
        return PinEntry(path=d["path"], fingerprint=d["fingerprint"], version=d.get("version"))


@dataclass
class PinResult:
    path: str
    ok: bool
    expected: Optional[str] = None
    actual: Optional[str] = None
    error: Optional[str] = None

    def __repr__(self) -> str:  # pragma: no cover
        status = "OK" if self.ok else "MISMATCH"
        return f"PinResult({self.path!r}, {status})"


@dataclass
class PinReport:
    results: List[PinResult] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for r in self.results if r.ok)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results if not r.ok)

    def summary(self) -> str:
        return f"{self.passed_count} pinned OK, {self.failed_count} mismatched"


def _fingerprint(data: dict) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def create_pin(client: VaultClient, path: str) -> PinEntry:
    data = client.read_secret(path)
    version = data.get("metadata", {}).get("version") if isinstance(data.get("metadata"), dict) else None
    secrets = {k: v for k, v in data.items() if k != "metadata"}
    return PinEntry(path=path, fingerprint=_fingerprint(secrets), version=version)


def save_pins(pins: List[PinEntry], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps([p.to_dict() for p in pins], indent=2))


def load_pins(src: Path) -> List[PinEntry]:
    return [PinEntry.from_dict(d) for d in json.loads(src.read_text())]


def verify_pins(client: VaultClient, pins: List[PinEntry]) -> PinReport:
    report = PinReport()
    for pin in pins:
        try:
            data = client.read_secret(pin.path)
            secrets = {k: v for k, v in data.items() if k != "metadata"}
            actual = _fingerprint(secrets)
            ok = actual == pin.fingerprint
            report.results.append(PinResult(path=pin.path, ok=ok, expected=pin.fingerprint, actual=actual))
        except Exception as exc:
            report.results.append(PinResult(path=pin.path, ok=False, error=str(exc)))
    return report
