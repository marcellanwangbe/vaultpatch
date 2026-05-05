"""Tests for vaultpatch.score."""
from unittest.mock import MagicMock

import pytest

from vaultpatch.score import (
    ScoreBreakdown,
    SecretScore,
    ScoreReport,
    _shannon_entropy,
    _grade,
    score_value,
    score_path,
    score_paths,
)


@pytest.fixture
def mock_client():
    return MagicMock()


def test_shannon_entropy_empty():
    assert _shannon_entropy("") == 0.0


def test_shannon_entropy_uniform():
    # single repeated character has entropy 0
    assert _shannon_entropy("aaaa") == pytest.approx(0.0)


def test_shannon_entropy_varied():
    val = _shannon_entropy("abcdefgh")
    assert val > 2.0


def test_grade_boundaries():
    assert _grade(95) == "A"
    assert _grade(75) == "B"
    assert _grade(55) == "C"
    assert _grade(35) == "D"
    assert _grade(10) == "F"


def test_score_value_weak_password():
    result = score_value("pw", "password")
    assert result.grade == "F"
    assert result.score < 35


def test_score_value_strong_secret():
    strong = "X7#kP!mQ2@nZ"
    result = score_value("api_key", strong)
    assert result.score >= 55
    assert result.grade in {"A", "B", "C"}


def test_score_value_all_lowercase_penalty():
    result = score_value("key", "abcdefghij")
    # penalty applied for all-lowercase
    result_no_penalty = score_value("key", "Abcdefghij")
    assert result.score <= result_no_penalty.score


def test_score_value_sets_key():
    result = score_value("my_key", "SomeValue1!")
    assert result.key == "my_key"
    assert result.path == ""  # path set externally


def test_score_path_reads_client(mock_client):
    mock_client.read_secret.return_value = ({"token": "AbCd1234!@#$"}, None)
    results = score_path(mock_client, "secret/app")
    assert len(results) == 1
    assert results[0].path == "secret/app"
    assert results[0].key == "token"
    assert results[0].ok


def test_score_path_filters_keys(mock_client):
    mock_client.read_secret.return_value = (
        {"token": "AbCd1234!@#$", "name": "plain"}, None
    )
    results = score_path(mock_client, "secret/app", keys=["token"])
    assert len(results) == 1
    assert results[0].key == "token"


def test_score_path_error_propagates(mock_client):
    mock_client.read_secret.return_value = (None, "permission denied")
    results = score_path(mock_client, "secret/missing")
    assert len(results) == 1
    assert not results[0].ok
    assert results[0].error == "permission denied"


def test_score_paths_aggregates(mock_client):
    mock_client.read_secret.side_effect = [
        ({"k1": "StrongPass1!"}, None),
        ({"k2": "weak"}, None),
    ]
    report = score_paths(mock_client, ["secret/a", "secret/b"])
    assert len(report.results) == 2
    assert report.average_score > 0


def test_score_report_summary(mock_client):
    mock_client.read_secret.return_value = ({"x": "Aa1!Bb2@Cc3#"}, None)
    report = score_paths(mock_client, ["secret/x"])
    s = report.summary()
    assert "1 key(s)" in s
    assert "avg=" in s
