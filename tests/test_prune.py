"""Tests for vaultpatch.prune."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultpatch.prune import (
    PruneReport,
    PruneResult,
    _is_stale,
    prune_path,
    prune_paths,
)


@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.read_secret.return_value = {
        "active_key": "supersecret",
        "empty_key": "",
        "null_key": "null",
        "none_key": "none",
    }
    return client


# --- _is_stale ---

def test_is_stale_empty_string():
    assert _is_stale("", empty_only=False) is True


def test_is_stale_null_string_not_empty_only():
    assert _is_stale("null", empty_only=False) is True


def test_is_stale_null_string_empty_only():
    assert _is_stale("null", empty_only=True) is False


def test_is_stale_valid_value():
    assert _is_stale("s3cr3t!", empty_only=False) is False


# --- prune_path ---

def test_prune_dry_run_does_not_write(mock_client):
    result = prune_path(mock_client, "secret/app", dry_run=True)
    mock_client.write_secret.assert_not_called()
    assert result.dry_run is True
    assert "empty_key" in result.pruned_keys


def test_prune_removes_stale_keys(mock_client):
    result = prune_path(mock_client, "secret/app", dry_run=False)
    assert result.ok
    assert "empty_key" in result.pruned_keys
    assert "null_key" in result.pruned_keys
    assert "none_key" in result.pruned_keys
    assert "active_key" not in result.pruned_keys
    mock_client.write_secret.assert_called_once()
    written = mock_client.write_secret.call_args[0][1]
    assert written == {"active_key": "supersecret"}


def test_prune_empty_only_skips_null_strings(mock_client):
    result = prune_path(mock_client, "secret/app", empty_only=True, dry_run=False)
    assert "empty_key" in result.pruned_keys
    assert "null_key" not in result.pruned_keys


def test_prune_path_not_found():
    client = MagicMock()
    client.read_secret.return_value = None
    result = prune_path(client, "secret/missing")
    assert not result.ok
    assert result.error == "path not found"
    client.write_secret.assert_not_called()


def test_prune_path_read_error():
    client = MagicMock()
    client.read_secret.side_effect = RuntimeError("connection refused")
    result = prune_path(client, "secret/broken")
    assert not result.ok
    assert "connection refused" in result.error


# --- prune_paths / PruneReport ---

def test_prune_paths_aggregates_results(mock_client):
    report = prune_paths(mock_client, ["secret/a", "secret/b"], dry_run=True)
    assert len(report.results) == 2
    assert report.pruned_count >= 0


def test_prune_report_summary_string(mock_client):
    report = prune_paths(mock_client, ["secret/a"], dry_run=False)
    summary = report.summary()
    assert "path(s)" in summary
    assert "error" in summary


def test_prune_report_error_count():
    client = MagicMock()
    client.read_secret.side_effect = RuntimeError("boom")
    report = prune_paths(client, ["secret/x", "secret/y"])
    assert report.error_count == 2
    assert report.pruned_count == 0
