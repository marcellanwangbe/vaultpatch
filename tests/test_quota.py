"""Tests for vaultpatch.quota."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultpatch.quota import QuotaViolation, check_quota


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_quota_no_violations(mock_client):
    mock_client.read_secret.return_value = {"key1": "value1", "key2": "value2"}
    report = check_quota(mock_client, ["secret/a"], max_keys=10, max_bytes=1024)
    assert report.ok
    assert report.violation_count == 0


def test_quota_exceeds_key_count(mock_client):
    mock_client.read_secret.return_value = {f"k{i}": "v" for i in range(5)}
    report = check_quota(mock_client, ["secret/a"], max_keys=3, max_bytes=4096)
    assert not report.ok
    assert report.violation_count == 1
    v = report.violations[0]
    assert v.exceeds_keys
    assert not v.exceeds_bytes
    assert v.key_count == 5
    assert v.max_keys == 3


def test_quota_exceeds_bytes(mock_client):
    mock_client.read_secret.return_value = {"key": "x" * 200}
    report = check_quota(mock_client, ["secret/b"], max_keys=20, max_bytes=50)
    assert not report.ok
    v = report.violations[0]
    assert v.exceeds_bytes
    assert v.value_bytes == 200


def test_quota_records_errors(mock_client):
    mock_client.read_secret.side_effect = RuntimeError("not found")
    report = check_quota(mock_client, ["secret/missing"], max_keys=10, max_bytes=1024)
    assert report.ok  # no violations — path errored
    assert report.error_count == 1
    assert "not found" in report.errors[0]


def test_quota_multiple_paths(mock_client):
    def _read(path):
        if path == "secret/big":
            return {f"k{i}": "v" for i in range(25)}
        return {"a": "b"}

    mock_client.read_secret.side_effect = _read
    report = check_quota(mock_client, ["secret/ok", "secret/big"], max_keys=20, max_bytes=4096)
    assert report.violation_count == 1
    assert report.violations[0].path == "secret/big"


def test_quota_summary_string(mock_client):
    mock_client.read_secret.return_value = {f"k{i}": "v" for i in range(5)}
    report = check_quota(mock_client, ["secret/a"], max_keys=2, max_bytes=4096)
    assert "1 violation" in report.summary()


def test_quota_summary_includes_errors(mock_client):
    mock_client.read_secret.side_effect = [RuntimeError("boom"), {f"k{i}": "v" for i in range(5)}]
    report = check_quota(mock_client, ["secret/err", "secret/big"], max_keys=2, max_bytes=4096)
    summary = report.summary()
    assert "violation" in summary
    assert "error" in summary


def test_violation_repr_contains_path():
    v = QuotaViolation(path="secret/x", key_count=5, max_keys=3, value_bytes=100, max_bytes=50)
    r = repr(v)
    assert "secret/x" in r
