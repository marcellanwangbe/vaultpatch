"""Tests for vaultpatch.verify."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.verify import VerifyReport, VerifyResult, verify_secrets
from vaultpatch.client import VaultClientError


@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.read_secret.return_value = {
        "API_KEY": "supersecret",
        "DB_PASS": "hunter2",
    }
    return client


def test_verify_all_pass(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"API_KEY": "supersecret", "DB_PASS": "hunter2"},
    )
    assert report.all_passed()
    assert report.passed_count == 2
    assert report.failed_count == 0


def test_verify_value_mismatch(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"API_KEY": "wrongvalue"},
    )
    assert not report.all_passed()
    assert report.failed_count == 1
    result = report.results[0]
    assert not result.passed
    assert "mismatch" in result.reason


def test_verify_missing_key(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"NONEXISTENT": "value"},
    )
    assert report.failed_count == 1
    assert "missing" in report.results[0].reason


def test_verify_path_not_found(mock_client):
    mock_client.read_secret.return_value = None
    report = verify_secrets(mock_client, "secret/gone", {"KEY": "val"})
    assert report.failed_count == 1
    assert "not found" in report.results[0].reason


def test_verify_read_error(mock_client):
    mock_client.read_secret.side_effect = VaultClientError("connection refused")
    report = verify_secrets(mock_client, "secret/app", {"KEY": "val"})
    assert report.failed_count == 1
    assert "read error" in report.results[0].reason


def test_verify_regex_match(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"API_KEY": r"^super"},
        use_regex=True,
    )
    assert report.all_passed()
    assert "matched" in report.results[0].reason


def test_verify_regex_no_match(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"API_KEY": r"^notmatching"},
        use_regex=True,
    )
    assert report.failed_count == 1
    assert "did not match" in report.results[0].reason


def test_verify_report_summary(mock_client):
    report = verify_secrets(
        mock_client,
        "secret/app",
        {"API_KEY": "supersecret", "DB_PASS": "wrong"},
    )
    summary = report.summary()
    assert "1 passed" in summary
    assert "1 failed" in summary
    assert "2 checks" in summary


def test_verify_empty_expected_keys(mock_client):
    """Verifying with no expected keys should produce an empty, passing report."""
    report = verify_secrets(mock_client, "secret/app", {})
    assert report.all_passed()
    assert report.passed_count == 0
    assert report.failed_count == 0
    assert report.results == []
