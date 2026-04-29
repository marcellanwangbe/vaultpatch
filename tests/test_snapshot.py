"""Tests for the snapshot module."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vaultpatch.snapshot import (
    Snapshot,
    capture_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)


def _make_snapshot(path="secret/app", namespace="ns1", data=None, captured_at=None):
    return Snapshot(
        path=path,
        namespace=namespace,
        data=data or {"key": "value"},
        captured_at=captured_at or time.time(),
    )


def test_snapshot_to_dict_round_trip():
    snap = _make_snapshot(captured_at=1700000000.0)
    d = snap.to_dict()
    restored = Snapshot.from_dict(d)
    assert restored.path == snap.path
    assert restored.namespace == snap.namespace
    assert restored.data == snap.data
    assert restored.captured_at == snap.captured_at


def test_save_and_load_snapshot(tmp_path):
    snap = _make_snapshot(data={"db_pass": "s3cr3t"}, captured_at=1700000001.0)
    out = tmp_path / "snap.json"
    save_snapshot(snap, out)
    assert out.exists()
    loaded = load_snapshot(out)
    assert loaded.data == snap.data
    assert loaded.path == snap.path


def test_save_snapshot_creates_parent_dirs(tmp_path):
    snap = _make_snapshot()
    out = tmp_path / "nested" / "dir" / "snap.json"
    save_snapshot(snap, out)
    assert out.exists()


def test_capture_snapshot_reads_client():
    mock_client = MagicMock()
    mock_client.config.namespace = "dev"
    mock_client.read_secret.return_value = {"api_key": "abc123"}
    snap = capture_snapshot(mock_client, "secret/svc")
    assert snap.path == "secret/svc"
    assert snap.namespace == "dev"
    assert snap.data == {"api_key": "abc123"}
    mock_client.read_secret.assert_called_once_with("secret/svc")


def test_capture_snapshot_handles_none_response():
    mock_client = MagicMock()
    mock_client.config.namespace = None
    mock_client.read_secret.return_value = None
    snap = capture_snapshot(mock_client, "secret/empty")
    assert snap.data == {}


def test_diff_snapshots_detects_changes():
    before = _make_snapshot(data={"key": "old", "stable": "same"})
    after = _make_snapshot(data={"key": "new", "stable": "same", "added": "val"})
    diff = diff_snapshots(before, after)
    assert diff.has_changes
    assert "key" in diff.changes
    assert "added" in diff.changes
    assert "stable" not in diff.changes


def test_diff_snapshots_no_changes():
    snap = _make_snapshot(data={"x": "1", "y": "2"})
    diff = diff_snapshots(snap, snap)
    assert not diff.has_changes
