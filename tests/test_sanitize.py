"""Tests for vaultpatch.sanitize."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultpatch.sanitize import (
    SanitizeReport,
    _detect_pattern,
    _redact,
    sanitize_secrets,
)


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------

def test_redact_short_value():
    assert _redact("ab") == "****"


def test_redact_long_value():
    result = _redact("AKIAIOSFODNN7EXAMPLE")
    assert result.startswith("AK")
    assert result.endswith("LE")
    assert "*" in result


def test_detect_aws_access_key():
    assert _detect_pattern("AKIAIOSFODNN7EXAMPLE123") == "aws_access_key"


def test_detect_github_token():
    token = "ghp_" + "A" * 36
    assert _detect_pattern(token) == "github_token"


def test_detect_private_key_header():
    assert _detect_pattern("-----BEGIN RSA PRIVATE KEY-----") == "private_key_header"


def test_detect_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert _detect_pattern(jwt) == "jwt"


def test_detect_hex_secret():
    assert _detect_pattern("a" * 32) == "hex_secret"


def test_detect_no_match():
    assert _detect_pattern("hello-world") is None


# ---------------------------------------------------------------------------
# sanitize_secrets integration
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_client():
    return MagicMock()


def test_sanitize_flags_aws_key(mock_client):
    mock_client.read_secret.return_value = {"api_key": "AKIAIOSFODNN7EXAMPLE123"}
    report = sanitize_secrets(mock_client, ["secret/app"])
    assert report.flagged_count == 1
    assert report.matches[0].path == "secret/app"
    assert report.matches[0].key == "api_key"
    assert report.matches[0].pattern_name == "aws_access_key"


def test_sanitize_clean_secret_no_flags(mock_client):
    mock_client.read_secret.return_value = {"username": "admin", "env": "production"}
    report = sanitize_secrets(mock_client, ["secret/safe"])
    assert report.flagged_count == 0


def test_sanitize_records_read_errors(mock_client):
    mock_client.read_secret.side_effect = Exception("permission denied")
    report = sanitize_secrets(mock_client, ["secret/locked"])
    assert report.error_count == 1
    assert "permission denied" in report.errors["secret/locked"]


def test_sanitize_multiple_paths(mock_client):
    mock_client.read_secret.side_effect = [
        {"token": "ghp_" + "B" * 36},
        {"password": "safe-password-123"},
    ]
    report = sanitize_secrets(mock_client, ["secret/a", "secret/b"])
    assert report.flagged_count == 1
    assert report.matches[0].path == "secret/a"


def test_sanitize_report_summary():
    report = SanitizeReport()
    assert "0 sensitive" in report.summary()
