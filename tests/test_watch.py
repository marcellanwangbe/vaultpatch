"""Tests for vaultpatch.watch drift-detection module."""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from vaultpatch.snapshot import Snapshot
from vaultpatch.watch import watch_once, watch_loop, DriftEvent, WatchReport


@pytest.fixture()
def mock_client():
    return MagicMock()


def _make_snapshot(secrets: dict) -> Snapshot:
    return Snapshot(namespace="ns", secrets=secrets, captured_at=0.0)


def test_watch_once_no_drift(mock_client):
    snapshot = _make_snapshot({"secret/a": {"key": "value"}})
    mock_client.read_secret.return_value = {"key": "value"}
    report = watch_once(mock_client, snapshot)
    assert report.drift_count == 0
    assert report.paths_checked == 1


def test_watch_once_detects_changed_value(mock_client):
    snapshot = _make_snapshot({"secret/a": {"key": "old"}})
    mock_client.read_secret.return_value = {"key": "new"}
    report = watch_once(mock_client, snapshot)
    assert report.drift_count == 1
    assert report.events[0].path == "secret/a"


def test_watch_once_detects_added_key(mock_client):
    snapshot = _make_snapshot({"secret/b": {"x": "1"}})
    mock_client.read_secret.return_value = {"x": "1", "y": "2"}
    report = watch_once(mock_client, snapshot)
    assert report.drift_count == 1


def test_watch_once_detects_removed_key(mock_client):
    snapshot = _make_snapshot({"secret/c": {"a": "1", "b": "2"}})
    mock_client.read_secret.return_value = {"a": "1"}
    report = watch_once(mock_client, snapshot)
    assert report.drift_count == 1


def test_watch_once_limits_to_given_paths(mock_client):
    snapshot = _make_snapshot({
        "secret/a": {"k": "v"},
        "secret/b": {"k": "v"},
    })
    mock_client.read_secret.return_value = {"k": "changed"}
    report = watch_once(mock_client, snapshot, paths=["secret/a"])
    assert report.paths_checked == 1


def test_watch_once_handles_client_error(mock_client):
    snapshot = _make_snapshot({"secret/err": {"key": "val"}})
    mock_client.read_secret.side_effect = Exception("connection error")
    # Should not raise; treats missing read as empty dict
    report = watch_once(mock_client, snapshot)
    assert report.paths_checked == 1
    assert report.drift_count == 1  # baseline has keys, current is empty


def test_watch_report_summary_string(mock_client):
    snapshot = _make_snapshot({"secret/x": {"a": "1"}})
    mock_client.read_secret.return_value = {"a": "2"}
    report = watch_once(mock_client, snapshot)
    summary = report.summary()
    assert "1" in summary
    assert "drift" in summary.lower()


def test_watch_loop_calls_on_drift(mock_client):
    snapshot = _make_snapshot({"secret/a": {"k": "old"}})
    mock_client.read_secret.return_value = {"k": "new"}
    reports = []
    watch_loop(mock_client, snapshot, interval=0, max_iterations=2, on_drift=reports.append)
    assert len(reports) == 2
    assert all(r.drift_count == 1 for r in reports)


def test_watch_loop_no_callback_when_no_drift(mock_client):
    snapshot = _make_snapshot({"secret/a": {"k": "same"}})
    mock_client.read_secret.return_value = {"k": "same"}
    called = []
    watch_loop(mock_client, snapshot, interval=0, max_iterations=3, on_drift=called.append)
    assert called == []
