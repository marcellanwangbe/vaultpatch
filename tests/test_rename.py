"""Tests for vaultpatch.rename."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.client import VaultClientError
from vaultpatch.rename import RenameReport, rename_many, rename_secret


@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.read_secret.return_value = {"API_KEY": "abc123", "TOKEN": "xyz"}
    client.write_secret.return_value = None
    client.delete_secret.return_value = None
    return client


def test_rename_dry_run_does_not_write(mock_client):
    result = rename_secret(mock_client, "secret/old", "secret/new", dry_run=True)
    assert result.ok is True
    assert result.dry_run is True
    assert result.keys_moved == 2
    mock_client.write_secret.assert_not_called()
    mock_client.delete_secret.assert_not_called()


def test_rename_applies_copy_and_delete(mock_client):
    result = rename_secret(mock_client, "secret/old", "secret/new", dry_run=False)
    assert result.ok is True
    assert result.dry_run is False
    assert result.keys_moved == 2
    mock_client.write_secret.assert_called_once_with("secret/new", {"API_KEY": "abc123", "TOKEN": "xyz"})
    mock_client.delete_secret.assert_called_once_with("secret/old")


def test_rename_no_delete_src_keeps_source(mock_client):
    result = rename_secret(mock_client, "secret/old", "secret/new", delete_src=False)
    assert result.ok is True
    mock_client.write_secret.assert_called_once()
    mock_client.delete_secret.assert_not_called()


def test_rename_source_not_found(mock_client):
    mock_client.read_secret.return_value = None
    result = rename_secret(mock_client, "secret/missing", "secret/new")
    assert result.ok is False
    assert "not found" in result.error
    mock_client.write_secret.assert_not_called()


def test_rename_read_error(mock_client):
    mock_client.read_secret.side_effect = VaultClientError("permission denied")
    result = rename_secret(mock_client, "secret/old", "secret/new")
    assert result.ok is False
    assert "permission denied" in result.error


def test_rename_write_error(mock_client):
    mock_client.write_secret.side_effect = VaultClientError("write failed")
    result = rename_secret(mock_client, "secret/old", "secret/new")
    assert result.ok is False
    assert "write failed" in result.error


def test_rename_many_returns_all_results(mock_client):
    pairs = [("secret/a", "secret/b"), ("secret/c", "secret/d")]
    report = rename_many(mock_client, pairs, dry_run=True)
    assert isinstance(report, RenameReport)
    assert len(report.results) == 2
    assert report.success_count == 2
    assert report.error_count == 0


def test_rename_report_summary_string(mock_client):
    mock_client.read_secret.side_effect = [None, {"K": "v"}]
    pairs = [("secret/missing", "secret/x"), ("secret/ok", "secret/y")]
    report = rename_many(mock_client, pairs, dry_run=True)
    summary = report.summary()
    assert "1 succeeded" in summary
    assert "1 failed" in summary
