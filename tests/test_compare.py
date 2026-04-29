"""Tests for vaultpatch.compare."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.compare import compare_paths, CompareReport, CompareResult
from vaultpatch.client import VaultClientError


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_compare_identical_paths(mock_client):
    data = {"key": "value"}
    mock_client.read_secret.return_value = data

    report = compare_paths(mock_client, [("secret/a", "secret/b")])

    assert len(report.results) == 1
    result = report.results[0]
    assert result.ok
    assert not result.diff.has_changes
    assert report.identical_count == 1
    assert report.differs_count == 0
    assert "IDENTICAL" in result.summary()


def test_compare_different_paths(mock_client):
    mock_client.read_secret.side_effect = [
        {"key": "old"},
        {"key": "new"},
    ]

    report = compare_paths(mock_client, [("secret/a", "secret/b")])

    result = report.results[0]
    assert result.ok
    assert result.diff.has_changes
    assert report.differs_count == 1
    assert "DIFFERS" in result.summary()


def test_compare_added_key(mock_client):
    mock_client.read_secret.side_effect = [
        {},
        {"new_key": "val"},
    ]

    report = compare_paths(mock_client, [("secret/a", "secret/b")])
    result = report.results[0]
    assert result.diff.has_changes
    assert "new_key" in result.diff.added


def test_compare_left_error(mock_client):
    mock_client.read_secret.side_effect = [
        VaultClientError("not found"),
        {"key": "val"},
    ]

    report = compare_paths(mock_client, [("secret/missing", "secret/b")])
    result = report.results[0]
    assert not result.ok
    assert result.left_error is not None
    assert report.error_count == 1
    assert "ERROR" in result.summary()


def test_compare_right_error(mock_client):
    mock_client.read_secret.side_effect = [
        {"key": "val"},
        VaultClientError("forbidden"),
    ]

    report = compare_paths(mock_client, [("secret/a", "secret/missing")])
    result = report.results[0]
    assert not result.ok
    assert result.right_error is not None


def test_compare_multiple_pairs(mock_client):
    mock_client.read_secret.side_effect = [
        {"x": "1"}, {"x": "1"},  # identical
        {"y": "a"}, {"y": "b"},  # differs
    ]

    report = compare_paths(
        mock_client,
        [("secret/a", "secret/b"), ("secret/c", "secret/d")],
    )

    assert len(report.results) == 2
    assert report.identical_count == 1
    assert report.differs_count == 1
    assert "2 compared" in report.summary()


def test_compare_report_summary_all_identical(mock_client):
    mock_client.read_secret.return_value = {"k": "v"}
    report = compare_paths(mock_client, [("a", "b"), ("c", "d")])
    assert "2 identical" in report.summary()
    assert "0 errors" in report.summary()
