"""Tests for vaultpatch.promote."""
from unittest.mock import MagicMock
import pytest

from vaultpatch.promote import promote_secret, PromoteReport, PromoteResult


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.read_secret.return_value = {
        "API_KEY": "abc123",
        "DB_PASS": "secret",
        "DEBUG": "true",
    }
    return client


def test_promote_copies_all_keys_by_default(mock_client):
    result = promote_secret(mock_client, "staging/app", "prod/app")
    assert result.ok
    assert set(result.keys_promoted) == {"API_KEY", "DB_PASS", "DEBUG"}
    assert result.skipped_keys == []
    mock_client.write_secret.assert_called_once()
    _, written = mock_client.write_secret.call_args[0]
    assert written["API_KEY"] == "abc123"


def test_promote_dry_run_does_not_write(mock_client):
    result = promote_secret(mock_client, "staging/app", "prod/app", dry_run=True)
    assert result.ok
    assert result.dry_run is True
    assert len(result.keys_promoted) == 3
    mock_client.write_secret.assert_not_called()


def test_promote_include_keys_filters(mock_client):
    result = promote_secret(
        mock_client, "staging/app", "prod/app", include_keys=["API_KEY"]
    )
    assert result.ok
    assert result.keys_promoted == ["API_KEY"]
    assert set(result.skipped_keys) == {"DB_PASS", "DEBUG"}
    _, written = mock_client.write_secret.call_args[0]
    assert list(written.keys()) == ["API_KEY"]


def test_promote_exclude_keys_filters(mock_client):
    result = promote_secret(
        mock_client, "staging/app", "prod/app", exclude_keys=["DEBUG"]
    )
    assert result.ok
    assert "DEBUG" not in result.keys_promoted
    assert "DEBUG" in result.skipped_keys
    _, written = mock_client.write_secret.call_args[0]
    assert "DEBUG" not in written


def test_promote_read_error_returns_error_result(mock_client):
    mock_client.read_secret.side_effect = RuntimeError("vault unreachable")
    result = promote_secret(mock_client, "staging/app", "prod/app")
    assert not result.ok
    assert "vault unreachable" in result.error
    mock_client.write_secret.assert_not_called()


def test_promote_write_error_returns_error_result(mock_client):
    mock_client.write_secret.side_effect = RuntimeError("permission denied")
    result = promote_secret(mock_client, "staging/app", "prod/app")
    assert not result.ok
    assert "permission denied" in result.error


def test_promote_report_summary():
    results = [
        PromoteResult(src_path="s/a", dst_path="p/a", keys_promoted=["K1"]),
        PromoteResult(src_path="s/b", dst_path="p/b", error="fail"),
    ]
    report = PromoteReport(results=results)
    assert report.success_count == 1
    assert report.error_count == 1
    summary = report.summary()
    assert "1 path(s)" in summary
    assert "1 error(s)" in summary


def test_promote_result_repr():
    r = PromoteResult(src_path="s/a", dst_path="p/a", keys_promoted=["X"], dry_run=True)
    assert "DRY-RUN" in repr(r)
    assert "s/a" in repr(r)
