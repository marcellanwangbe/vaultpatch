"""Tests for vaultpatch.clone."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultpatch.clone import CloneReport, CloneResult, clone_secret


@pytest.fixture()
def mock_client() -> MagicMock:
    client = MagicMock()
    client.read_secret.return_value = {
        "DB_PASS": "s3cr3t",
        "API_KEY": "abc123",
        "TOKEN": "tok",
    }
    return client


def test_clone_copies_all_keys_by_default(mock_client: MagicMock) -> None:
    result = clone_secret(mock_client, "src/path", "dst/path")
    assert result.ok
    assert set(result.keys_copied) == {"DB_PASS", "API_KEY", "TOKEN"}
    assert result.keys_skipped == []
    mock_client.write_secret.assert_called_once()


def test_clone_dry_run_does_not_write(mock_client: MagicMock) -> None:
    result = clone_secret(mock_client, "src/path", "dst/path", dry_run=True)
    assert result.ok
    assert result.dry_run is True
    mock_client.write_secret.assert_not_called()


def test_clone_include_keys_filters(mock_client: MagicMock) -> None:
    result = clone_secret(
        mock_client, "src/path", "dst/path", include_keys=["DB_PASS"]
    )
    assert result.ok
    assert result.keys_copied == ["DB_PASS"]
    assert set(result.keys_skipped) == {"API_KEY", "TOKEN"}
    written_data = mock_client.write_secret.call_args[0][1]
    assert list(written_data.keys()) == ["DB_PASS"]


def test_clone_exclude_keys_filters(mock_client: MagicMock) -> None:
    result = clone_secret(
        mock_client, "src/path", "dst/path", exclude_keys=["TOKEN"]
    )
    assert result.ok
    assert "TOKEN" not in result.keys_copied
    assert "TOKEN" in result.keys_skipped


def test_clone_read_error_returns_error_result(mock_client: MagicMock) -> None:
    mock_client.read_secret.side_effect = RuntimeError("not found")
    result = clone_secret(mock_client, "bad/path", "dst/path")
    assert not result.ok
    assert "not found" in result.error
    mock_client.write_secret.assert_not_called()


def test_clone_write_error_returns_error_result(mock_client: MagicMock) -> None:
    mock_client.write_secret.side_effect = RuntimeError("permission denied")
    result = clone_secret(mock_client, "src/path", "dst/path")
    assert not result.ok
    assert "permission denied" in result.error


def test_clone_report_counts() -> None:
    results = [
        CloneResult("a", "b", keys_copied=["k1"]),
        CloneResult("c", "d", error="oops"),
        CloneResult("e", "f", keys_copied=["k2"], dry_run=True),
    ]
    report = CloneReport(results=results)
    assert report.success_count == 2
    assert report.error_count == 1
    assert "2 path(s)" in report.summary()
    assert "1 error" in report.summary()
