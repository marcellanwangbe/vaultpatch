"""Tests for vaultpatch.rollback."""

from __future__ import annotations

import json
import pathlib
from unittest.mock import MagicMock, patch

import pytest

from vaultpatch.rollback import SecretRollback, RollbackReport
from vaultpatch.snapshot import Snapshot


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_client(secrets: dict | None = None) -> MagicMock:
    client = MagicMock()
    secrets = secrets or {}
    client.read_secret.side_effect = lambda path: secrets.get(path, {})
    client.write_secret.return_value = None
    return client


def _write_snapshot(tmp_path: pathlib.Path, data: dict) -> str:
    snap_file = tmp_path / "snap.json"
    snap_file.write_text(json.dumps(data))
    return str(snap_file)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_rollback_dry_run_does_not_write(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {"secret/app": {"key": "old_value"}},
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = _make_client({"secret/app": {"key": "new_value"}})

    rollback = SecretRollback(client, dry_run=True)
    report = rollback.rollback_from_snapshot(snap_path)

    assert report.applied_count == 1
    assert report.results[0].dry_run is True
    client.write_secret.assert_not_called()


def test_rollback_applies_changes(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {"secret/app": {"key": "old_value"}},
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = _make_client({"secret/app": {"key": "current_value"}})

    rollback = SecretRollback(client, dry_run=False)
    report = rollback.rollback_from_snapshot(snap_path)

    assert report.applied_count == 1
    client.write_secret.assert_called_once_with(
        "secret/app", {"key": "old_value"}
    )


def test_rollback_skips_when_no_changes(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {"secret/app": {"key": "same_value"}},
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = _make_client({"secret/app": {"key": "same_value"}})

    rollback = SecretRollback(client, dry_run=False)
    report = rollback.rollback_from_snapshot(snap_path)

    assert report.applied_count == 0
    assert report.skipped_count == 1
    client.write_secret.assert_not_called()


def test_rollback_filters_by_paths(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {
            "secret/app": {"key": "old"},
            "secret/db": {"pass": "old_pass"},
        },
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = _make_client({
        "secret/app": {"key": "new"},
        "secret/db": {"pass": "new_pass"},
    })

    rollback = SecretRollback(client, dry_run=False)
    report = rollback.rollback_from_snapshot(snap_path, paths=["secret/app"])

    assert len(report.results) == 1
    assert report.results[0].path == "secret/app"


def test_rollback_records_error_on_exception(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {"secret/broken": {"k": "v"}},
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = MagicMock()
    client.read_secret.side_effect = RuntimeError("vault unavailable")

    rollback = SecretRollback(client, dry_run=False)
    report = rollback.rollback_from_snapshot(snap_path)

    assert report.error_count == 1
    assert "vault unavailable" in report.results[0].error


def test_rollback_report_summary(tmp_path):
    snap_data = {
        "captured_at": "2024-01-01T00:00:00",
        "secrets": {"secret/app": {"key": "old"}},
    }
    snap_path = _write_snapshot(tmp_path, snap_data)
    client = _make_client({"secret/app": {"key": "new"}})

    rollback = SecretRollback(client, dry_run=False)
    report = rollback.rollback_from_snapshot(snap_path)

    summary = report.summary()
    assert "1 applied" in summary
    assert "0 errors" in summary
