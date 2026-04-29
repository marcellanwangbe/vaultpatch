"""Tests for vaultpatch.search module."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.search import SearchMatch, SearchReport, search_secrets, _mask_value


@pytest.fixture
def mock_client():
    client = MagicMock()
    client.read_secret.side_effect = lambda path: {
        "secret/app/db": {"DB_PASSWORD": "supersecret123", "DB_USER": "admin"},
        "secret/app/api": {"API_KEY": "abcdef7890", "TIMEOUT": "30"},
        "secret/app/empty": {},
    }.get(path, {})
    return client


def test_mask_short_value():
    assert _mask_value("abc") == "****"


def test_mask_long_value():
    result = _mask_value("supersecret")
    assert result.startswith("su")
    assert result.endswith("et")
    assert "****" in result


def test_search_by_key_pattern(mock_client):
    paths = ["secret/app/db", "secret/app/api"]
    report = search_secrets(mock_client, paths, pattern="password", search_keys=True)
    assert report.total == 1
    assert report.matches[0].key == "DB_PASSWORD"
    assert report.matches[0].path == "secret/app/db"


def test_search_by_value_pattern(mock_client):
    paths = ["secret/app/db", "secret/app/api"]
    report = search_secrets(
        mock_client, paths, pattern="abcdef", search_keys=False, search_values=True
    )
    assert report.total == 1
    assert report.matches[0].key == "API_KEY"


def test_search_case_insensitive(mock_client):
    paths = ["secret/app/db"]
    report = search_secrets(mock_client, paths, pattern="db_user", search_keys=True)
    assert report.total == 1


def test_search_case_sensitive_no_match(mock_client):
    paths = ["secret/app/db"]
    report = search_secrets(
        mock_client, paths, pattern="db_user", search_keys=True, case_sensitive=True
    )
    assert report.total == 0


def test_search_empty_path_skipped(mock_client):
    paths = ["secret/app/empty"]
    report = search_secrets(mock_client, paths, pattern=".*", search_keys=True)
    assert report.total == 0


def test_search_client_error_skipped():
    client = MagicMock()
    client.read_secret.side_effect = Exception("connection error")
    report = search_secrets(client, ["secret/broken"], pattern="key")
    assert report.total == 0


def test_search_report_summary(mock_client):
    paths = ["secret/app/db", "secret/app/api"]
    report = search_secrets(
        mock_client, paths, pattern="key", search_keys=True, search_values=False
    )
    summary = report.summary()
    assert "matched" in summary
    assert str(report.total) in summary


def test_search_match_repr():
    m = SearchMatch(path="secret/app", key="TOKEN", masked_value="ab****ef")
    assert "secret/app" in repr(m)
    assert "TOKEN" in repr(m)
