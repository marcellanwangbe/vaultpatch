"""Tests for vaultpatch.pin."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vaultpatch.pin import (
    PinEntry,
    PinReport,
    PinResult,
    _fingerprint,
    create_pin,
    load_pins,
    save_pins,
    verify_pins,
)


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_fingerprint_is_deterministic():
    data = {"b": "2", "a": "1"}
    assert _fingerprint(data) == _fingerprint({"a": "1", "b": "2"})


def test_fingerprint_changes_with_value():
    assert _fingerprint({"key": "v1"}) != _fingerprint({"key": "v2"})


def test_create_pin_returns_entry(mock_client):
    mock_client.read_secret.return_value = {"password": "s3cr3t"}
    entry = create_pin(mock_client, "secret/app")
    assert entry.path == "secret/app"
    assert entry.fingerprint == _fingerprint({"password": "s3cr3t"})
    assert entry.version is None


def test_create_pin_excludes_metadata(mock_client):
    mock_client.read_secret.return_value = {"password": "abc", "metadata": {"version": 3}}
    entry = create_pin(mock_client, "secret/app")
    assert entry.fingerprint == _fingerprint({"password": "abc"})


def test_save_and_load_pins(tmp_path):
    pins = [
        PinEntry(path="secret/a", fingerprint="aabbcc", version=1),
        PinEntry(path="secret/b", fingerprint="ddeeff"),
    ]
    dest = tmp_path / "pins.json"
    save_pins(pins, dest)
    loaded = load_pins(dest)
    assert len(loaded) == 2
    assert loaded[0].path == "secret/a"
    assert loaded[0].fingerprint == "aabbcc"
    assert loaded[0].version == 1
    assert loaded[1].version is None


def test_save_pins_creates_parent_dirs(tmp_path):
    dest = tmp_path / "deep" / "dir" / "pins.json"
    save_pins([PinEntry(path="x", fingerprint="ff")], dest)
    assert dest.exists()


def test_verify_pins_all_pass(mock_client):
    mock_client.read_secret.return_value = {"token": "abc"}
    fp = _fingerprint({"token": "abc"})
    pins = [PinEntry(path="secret/x", fingerprint=fp)]
    report = verify_pins(mock_client, pins)
    assert report.passed_count == 1
    assert report.failed_count == 0
    assert report.results[0].ok is True


def test_verify_pins_detects_mismatch(mock_client):
    mock_client.read_secret.return_value = {"token": "changed"}
    pins = [PinEntry(path="secret/x", fingerprint="oldhash")]
    report = verify_pins(mock_client, pins)
    assert report.failed_count == 1
    result = report.results[0]
    assert result.ok is False
    assert result.expected == "oldhash"
    assert result.actual == _fingerprint({"token": "changed"})


def test_verify_pins_records_error(mock_client):
    mock_client.read_secret.side_effect = Exception("connection refused")
    pins = [PinEntry(path="secret/missing", fingerprint="abc")]
    report = verify_pins(mock_client, pins)
    assert report.failed_count == 1
    assert "connection refused" in report.results[0].error


def test_pin_report_summary():
    report = PinReport(results=[
        PinResult(path="a", ok=True),
        PinResult(path="b", ok=False),
        PinResult(path="c", ok=False),
    ])
    assert report.summary() == "1 pinned OK, 2 mismatched"
