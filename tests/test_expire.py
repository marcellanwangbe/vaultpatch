"""Tests for vaultpatch.expire."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from vaultpatch.expire import ExpireReport, ExpireResult, _age_days_from_metadata, check_expiry


# ---------------------------------------------------------------------------
# _age_days_from_metadata
# ---------------------------------------------------------------------------

def test_age_days_returns_none_for_empty_metadata():
    assert _age_days_from_metadata({}) is None


def test_age_days_parses_created_time():
    old = (datetime.now(tz=timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    age = _age_days_from_metadata({"created_time": old})
    assert age is not None
    assert 29.9 < age < 30.1


def test_age_days_returns_none_for_bad_format():
    age = _age_days_from_metadata({"created_time": "not-a-date"})
    assert age is None


# ---------------------------------------------------------------------------
# check_expiry
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_client():
    return MagicMock()


def _secret_with_age(days_old: float) -> dict:
    created = (datetime.now(tz=timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"data": {"key": "value"}, "metadata": {"created_time": created}}


def test_check_expiry_not_expired(mock_client):
    mock_client.read_secret.return_value = _secret_with_age(10)
    report = check_expiry(mock_client, ["secret/young"], ttl_days=90)
    assert len(report.results) == 1
    result = report.results[0]
    assert not result.expired
    assert result.ok
    assert report.expired_count == 0


def test_check_expiry_expired(mock_client):
    mock_client.read_secret.return_value = _secret_with_age(120)
    report = check_expiry(mock_client, ["secret/old"], ttl_days=90)
    result = report.results[0]
    assert result.expired
    assert report.expired_count == 1


def test_check_expiry_no_metadata(mock_client):
    mock_client.read_secret.return_value = {"data": {"k": "v"}}
    report = check_expiry(mock_client, ["secret/nometa"], ttl_days=90)
    result = report.results[0]
    assert result.age_days is None
    assert not result.expired


def test_check_expiry_client_error(mock_client):
    mock_client.read_secret.side_effect = RuntimeError("connection refused")
    report = check_expiry(mock_client, ["secret/broken"], ttl_days=90)
    result = report.results[0]
    assert not result.ok
    assert "connection refused" in result.error
    assert report.error_count == 1


def test_check_expiry_multiple_paths(mock_client):
    mock_client.read_secret.side_effect = [
        _secret_with_age(10),
        _secret_with_age(200),
    ]
    report = check_expiry(mock_client, ["a", "b"], ttl_days=90)
    assert report.expired_count == 1
    assert len(report.results) == 2


def test_expire_report_summary():
    results = [
        ExpireResult(path="a", age_days=10, expired=False, ok=True, error=None),
        ExpireResult(path="b", age_days=120, expired=True, ok=True, error=None),
        ExpireResult(path="c", age_days=None, expired=False, ok=False, error="timeout"),
    ]
    report = ExpireReport(results=results)
    assert report.expired_count == 1
    assert report.error_count == 1
    assert len(report.results) == 3
