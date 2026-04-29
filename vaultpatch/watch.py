"""Secret watch module: periodically checks secrets for drift against a snapshot."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient
from vaultpatch.diff import compute_diff, SecretDiff
from vaultpatch.snapshot import Snapshot


@dataclass
class DriftEvent:
    path: str
    diff: SecretDiff
    detected_at: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        return f"DriftEvent(path={self.path!r}, changes={self.diff.summary()})"


@dataclass
class WatchReport:
    events: List[DriftEvent] = field(default_factory=list)
    paths_checked: int = 0
    elapsed_seconds: float = 0.0

    @property
    def drift_count(self) -> int:
        return len(self.events)

    def summary(self) -> str:
        return (
            f"Checked {self.paths_checked} path(s) in {self.elapsed_seconds:.2f}s — "
            f"{self.drift_count} drift(s) detected."
        )


def watch_once(
    client: VaultClient,
    snapshot: Snapshot,
    paths: Optional[List[str]] = None,
) -> WatchReport:
    """Compare current secret values against a snapshot; return a WatchReport."""
    start = time.monotonic()
    target_paths = paths if paths is not None else list(snapshot.secrets.keys())
    events: List[DriftEvent] = []

    for path in target_paths:
        baseline = snapshot.secrets.get(path, {})
        try:
            current = client.read_secret(path) or {}
        except Exception:
            current = {}
        diff = compute_diff(baseline, current)
        if diff.has_changes():
            events.append(DriftEvent(path=path, diff=diff))

    elapsed = time.monotonic() - start
    return WatchReport(
        events=events,
        paths_checked=len(target_paths),
        elapsed_seconds=elapsed,
    )


def watch_loop(
    client: VaultClient,
    snapshot: Snapshot,
    interval: float = 30.0,
    max_iterations: Optional[int] = None,
    on_drift=None,
) -> None:
    """Continuously poll secrets for drift. Calls on_drift(WatchReport) when drift found."""
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        report = watch_once(client, snapshot)
        if report.drift_count > 0 and on_drift:
            on_drift(report)
        iteration += 1
        if max_iterations is None or iteration < max_iterations:
            time.sleep(interval)
