"""Tests for vaultpatch.baseline."""
from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vaultpatch.baseline import (
    BaselineDrift,
    BaselineEntry,
    capture_baseline,
    compare_baseline,
    load_baseline,
    save_baseline,
)


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_baseline_entry_round_trip():
    entry = BaselineEntry(path="secret/app", keys=["KEY_A", "KEY_B"], captured_at=1234.0)
    restored = BaselineEntry.from_dict(entry.to_dict())
    assert restored.path == entry.path
    assert restored.keys == entry.keys
    assert restored.captured_at == entry.captured_at


def test_baseline_drift_has_drift_true():
    d = BaselineDrift(path="secret/app", added_keys=["NEW"], removed_keys=[])
    assert d.has_drift is True


def test_baseline_drift_has_drift_false():
    d = BaselineDrift(path="secret/app", added_keys=[], removed_keys=[])
    assert d.has_drift is False


def test_baseline_drift_summary_shows_counts():
    d = BaselineDrift(path="secret/app", added_keys=["A"], removed_keys=["B", "C"])
    s = d.summary()
    assert "+1 added" in s
    assert "-2 removed" in s


def test_capture_baseline_records_keys(mock_client):
    mock_client.read_secret.side_effect = lambda p: {"FOO": "1", "BAR": "2"} if p == "secret/x" else {}
    entries = capture_baseline(mock_client, ["secret/x"])
    assert len(entries) == 1
    assert sorted(entries[0].keys) == ["BAR", "FOO"]


def test_capture_baseline_handles_none(mock_client):
    mock_client.read_secret.return_value = None
    entries = capture_baseline(mock_client, ["secret/missing"])
    assert entries[0].keys == []


def test_save_and_load_baseline(tmp_path):
    dest = tmp_path / "sub" / "baseline.json"
    entries = [BaselineEntry(path="secret/app", keys=["A"], captured_at=999.0)]
    save_baseline(entries, dest)
    assert dest.exists()
    loaded = load_baseline(dest)
    assert loaded[0].path == "secret/app"
    assert loaded[0].keys == ["A"]


def test_compare_baseline_no_drift(mock_client):
    mock_client.read_secret.return_value = {"A": "1", "B": "2"}
    entries = [BaselineEntry(path="secret/app", keys=["A", "B"])]
    drifts = compare_baseline(mock_client, entries)
    assert not drifts[0].has_drift


def test_compare_baseline_detects_added_key(mock_client):
    mock_client.read_secret.return_value = {"A": "1", "B": "2", "C": "3"}
    entries = [BaselineEntry(path="secret/app", keys=["A", "B"])]
    drifts = compare_baseline(mock_client, entries)
    assert "C" in drifts[0].added_keys
    assert drifts[0].removed_keys == []


def test_compare_baseline_detects_removed_key(mock_client):
    mock_client.read_secret.return_value = {"A": "1"}
    entries = [BaselineEntry(path="secret/app", keys=["A", "B"])]
    drifts = compare_baseline(mock_client, entries)
    assert "B" in drifts[0].removed_keys
    assert drifts[0].added_keys == []
