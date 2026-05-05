"""Tests for vaultpatch.redact module."""
from unittest.mock import MagicMock
import pytest

from vaultpatch.redact import (
    RedactReport,
    RedactResult,
    _is_sensitive,
    redact_secrets,
    REDACTED_PLACEHOLDER,
    DEFAULT_SENSITIVE_PATTERNS,
)


@pytest.fixture
def mock_client():
    return MagicMock()


def test_is_sensitive_matches_password():
    assert _is_sensitive("db_password", DEFAULT_SENSITIVE_PATTERNS)


def test_is_sensitive_matches_token():
    assert _is_sensitive("API_TOKEN", DEFAULT_SENSITIVE_PATTERNS)


def test_is_sensitive_does_not_match_safe_key():
    assert not _is_sensitive("hostname", DEFAULT_SENSITIVE_PATTERNS)


def test_is_sensitive_custom_pattern():
    assert _is_sensitive("db_host", [r"(?i)host"])


def test_redact_replaces_sensitive_values(mock_client):
    mock_client.read_secret.return_value = {
        "username": "admin",
        "password": "s3cr3t",
    }
    report = redact_secrets(mock_client, ["secret/app"])
    result = report.results[0]
    assert result.redacted["username"] == "admin"
    assert result.redacted["password"] == REDACTED_PLACEHOLDER
    assert "password" in result.redacted_keys


def test_redact_preserves_original(mock_client):
    mock_client.read_secret.return_value = {"api_key": "abc123", "host": "localhost"}
    report = redact_secrets(mock_client, ["secret/svc"])
    result = report.results[0]
    assert result.original["api_key"] == "abc123"
    assert result.redacted["api_key"] == REDACTED_PLACEHOLDER


def test_redact_no_sensitive_keys(mock_client):
    mock_client.read_secret.return_value = {"host": "db.example.com", "port": "5432"}
    report = redact_secrets(mock_client, ["secret/db"])
    result = report.results[0]
    assert result.redacted_keys == []
    assert result.redacted == result.original


def test_redact_empty_secret(mock_client):
    mock_client.read_secret.return_value = {}
    report = redact_secrets(mock_client, ["secret/empty"])
    assert report.results[0].redacted == {}


def test_redact_extra_patterns(mock_client):
    mock_client.read_secret.return_value = {"db_host": "127.0.0.1"}
    report = redact_secrets(mock_client, ["secret/x"], extra_patterns=[r"(?i)host"])
    assert report.results[0].redacted["db_host"] == REDACTED_PLACEHOLDER


def test_redact_custom_placeholder(mock_client):
    mock_client.read_secret.return_value = {"password": "hunter2"}
    report = redact_secrets(mock_client, ["secret/y"], placeholder="[HIDDEN]")
    assert report.results[0].redacted["password"] == "[HIDDEN]"


def test_report_summary_counts(mock_client):
    mock_client.read_secret.side_effect = [
        {"token": "t1", "name": "app"},
        {"secret": "s1", "env": "prod"},
    ]
    report = redact_secrets(mock_client, ["path/a", "path/b"])
    assert report.total_redacted_keys == 2
    assert "2 key(s)" in report.summary()
    assert "2 path(s)" in report.summary()


def test_redact_result_ok_flag(mock_client):
    mock_client.read_secret.return_value = {"k": "v"}
    report = redact_secrets(mock_client, ["secret/z"])
    assert report.results[0].ok is True


def test_redact_result_repr(mock_client):
    mock_client.read_secret.return_value = {"password": "x"}
    report = redact_secrets(mock_client, ["secret/repr"])
    r = repr(report.results[0])
    assert "secret/repr" in r
    assert "password" in r
