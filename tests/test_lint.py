"""Tests for vaultpatch.lint."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from vaultpatch.lint import (
    LintViolation,
    LintResult,
    LintReport,
    lint_path,
    lint_paths,
)


@pytest.fixture()
def mock_client():
    return MagicMock()


def test_lint_path_ok(mock_client):
    mock_client.read_secret.return_value = {"API_KEY": "SuperSecret1"}
    result = lint_path(mock_client, "secret/app")
    assert result.ok
    assert result.violations == []


def test_lint_path_empty_value(mock_client):
    mock_client.read_secret.return_value = {"TOKEN": ""}
    result = lint_path(mock_client, "secret/app")
    assert not result.ok
    violation_rules = [v.rule for v in result.violations]
    assert "no_empty_value" in violation_rules


def test_lint_path_short_value(mock_client):
    mock_client.read_secret.return_value = {"TOKEN": "Ab1"}
    result = lint_path(mock_client, "secret/app")
    rules = [v.rule for v in result.violations]
    assert "min_length_8" in rules


def test_lint_path_no_uppercase(mock_client):
    mock_client.read_secret.return_value = {"TOKEN": "abcdefgh1"}
    result = lint_path(mock_client, "secret/app")
    rules = [v.rule for v in result.violations]
    assert "has_uppercase" in rules


def test_lint_path_no_digit(mock_client):
    mock_client.read_secret.return_value = {"TOKEN": "Abcdefgh"}
    result = lint_path(mock_client, "secret/app")
    rules = [v.rule for v in result.violations]
    assert "has_digit" in rules


def test_lint_path_whitespace(mock_client):
    mock_client.read_secret.return_value = {"TOKEN": "Secret 1abc"}
    result = lint_path(mock_client, "secret/app", rules=["no_whitespace"])
    rules = [v.rule for v in result.violations]
    assert "no_whitespace" in rules


def test_lint_path_forbidden_key(mock_client):
    mock_client.read_secret.return_value = {"password": "SuperSecret1"}
    result = lint_path(mock_client, "secret/app", forbidden_keys=["password"])
    assert not result.ok
    assert any(v.rule == "forbidden_key" for v in result.violations)


def test_lint_path_client_error(mock_client):
    mock_client.read_secret.side_effect = RuntimeError("connection refused")
    result = lint_path(mock_client, "secret/app")
    assert result.error == "connection refused"
    assert not result.ok


def test_lint_paths_report(mock_client):
    mock_client.read_secret.side_effect = [
        {"KEY": "GoodPass1"},
        {"KEY": "bad"},
    ]
    report = lint_paths(mock_client, ["secret/a", "secret/b"])
    assert len(report.results) == 2
    assert report.violation_count > 0


def test_lint_report_summary_clean(mock_client):
    mock_client.read_secret.return_value = {"API_KEY": "SuperSecret1"}
    report = lint_paths(mock_client, ["secret/a"])
    assert "0 violation" in report.summary()
    assert "0 error" in report.summary()


def test_lint_result_summary_error():
    result = LintResult(path="secret/x", error="timeout")
    assert "ERROR" in result.summary()


def test_lint_violation_str():
    v = LintViolation("secret/x", "TOKEN", "min_length_8", "Too short")
    assert "secret/x" in str(v)
    assert "TOKEN" in str(v)
