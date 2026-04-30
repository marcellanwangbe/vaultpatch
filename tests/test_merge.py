"""Tests for vaultpatch.merge."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.merge import MergeReport, MergeResult, merge_secrets


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_merge_adds_new_keys(mock_client):
    mock_client.read_secret.side_effect = [
        {"A": "1", "B": "2"},  # src
        {},  # dst (empty)
    ]
    result = merge_secrets(mock_client, "src/path", "dst/path")
    assert result.ok
    assert sorted(result.merged_keys) == ["A", "B"]
    assert result.skipped_keys == []
    mock_client.write_secret.assert_called_once_with("dst/path", {"A": "1", "B": "2"})


def test_merge_skips_existing_keys_without_overwrite(mock_client):
    mock_client.read_secret.side_effect = [
        {"A": "1", "B": "2"},
        {"A": "old"},
    ]
    result = merge_secrets(mock_client, "src/path", "dst/path", overwrite=False)
    assert result.ok
    assert result.merged_keys == ["B"]
    assert result.skipped_keys == ["A"]


def test_merge_overwrites_existing_keys_when_flag_set(mock_client):
    mock_client.read_secret.side_effect = [
        {"A": "new"},
        {"A": "old"},
    ]
    result = merge_secrets(mock_client, "src/path", "dst/path", overwrite=True)
    assert result.ok
    assert result.merged_keys == ["A"]
    assert result.skipped_keys == []
    mock_client.write_secret.assert_called_once_with("dst/path", {"A": "new"})


def test_merge_dry_run_does_not_write(mock_client):
    mock_client.read_secret.side_effect = [
        {"X": "1"},
        {},
    ]
    result = merge_secrets(mock_client, "src/path", "dst/path", dry_run=True)
    assert result.ok
    assert result.merged_keys == ["X"]
    mock_client.write_secret.assert_not_called()


def test_merge_src_read_error_returns_error(mock_client):
    mock_client.read_secret.side_effect = RuntimeError("not found")
    result = merge_secrets(mock_client, "bad/src", "dst/path")
    assert not result.ok
    assert "read src failed" in result.error


def test_merge_write_error_returns_error(mock_client):
    mock_client.read_secret.side_effect = [{"K": "v"}, {}]
    mock_client.write_secret.side_effect = RuntimeError("permission denied")
    result = merge_secrets(mock_client, "src/path", "dst/path")
    assert not result.ok
    assert "write failed" in result.error


def test_merge_report_summary():
    report = MergeReport(
        results=[
            MergeResult(path="a", merged_keys=["x", "y"]),
            MergeResult(path="b", merged_keys=["z"]),
            MergeResult(path="c", error="boom"),
        ]
    )
    assert report.success_count == 2
    assert report.error_count == 1
    assert report.total_merged_keys == 3
    assert "2 path(s) merged" in report.summary()
    assert "1 error(s)" in report.summary()
    assert "3 key(s) written" in report.summary()
