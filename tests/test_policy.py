"""Tests for vaultpatch.policy module."""
import pytest
from vaultpatch.policy import SecretPolicy, PolicyViolation, PolicyResult


def test_policy_passes_valid_secrets():
    policy = SecretPolicy(min_length=4)
    result = policy.validate("secret/app", {"api_key": "abcd1234"})
    assert result.passed


def test_policy_fails_short_value():
    policy = SecretPolicy(min_length=12)
    result = policy.validate("secret/app", {"token": "short"})
    assert not result.passed
    assert any("too short" in v.reason for v in result.violations)


def test_policy_fails_forbidden_key():
    policy = SecretPolicy(forbidden_keys=["password"])
    result = policy.validate("secret/app", {"password": "supersecretvalue"})
    assert not result.passed
    assert result.violations[0].key == "password"
    assert "forbidden" in result.violations[0].reason


def test_policy_requires_uppercase():
    policy = SecretPolicy(require_uppercase=True, min_length=1)
    result = policy.validate("secret/app", {"key": "alllowercase"})
    assert not result.passed
    assert any("uppercase" in v.reason for v in result.violations)


def test_policy_requires_digit():
    policy = SecretPolicy(require_digit=True, min_length=1)
    result = policy.validate("secret/app", {"key": "NoDigitsHere"})
    assert not result.passed
    assert any("digit" in v.reason for v in result.violations)


def test_policy_key_pattern_mismatch():
    policy = SecretPolicy(key_pattern=r"^[a-z_]+$", min_length=1)
    result = policy.validate("secret/app", {"BAD-KEY": "value1"})
    assert not result.passed
    assert any("pattern" in v.reason for v in result.violations)


def test_policy_key_pattern_match():
    policy = SecretPolicy(key_pattern=r"^[a-z_]+$", min_length=1)
    result = policy.validate("secret/app", {"good_key": "value1"})
    assert result.passed


def test_policy_result_summary_passed():
    result = PolicyResult()
    assert "passed" in result.summary()


def test_policy_result_summary_failed():
    result = PolicyResult(violations=[
        PolicyViolation("secret/app", "key", "some reason")
    ])
    assert "failed" in result.summary()
    assert "some reason" in result.summary()


def test_violation_str():
    v = PolicyViolation("secret/db", "pass", "too short")
    assert "secret/db" in str(v)
    assert "pass" in str(v)
    assert "too short" in str(v)


def test_multiple_violations_collected():
    policy = SecretPolicy(
        min_length=20,
        require_uppercase=True,
        require_digit=True,
        min_length=20,
    )
    result = policy.validate("secret/app", {"key": "short"})
    # at least min_length + uppercase + digit violations
    assert len(result.violations) >= 3
