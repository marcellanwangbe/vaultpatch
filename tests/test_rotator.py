"""Tests for vaultpatch.rotator."""

from unittest.mock import MagicMock

import pytest

from vaultpatch.rotator import SecretRotator


@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.read_secret.return_value = {"password": "old_pass", "user": "admin"}
    return client


def test_rotate_dry_run_does_not_write(mock_client):
    rotator = SecretRotator(mock_client, dry_run=True)
    result = rotator.rotate("kv/app", {"password": "new_pass"})

    mock_client.write_secret.assert_not_called()
    assert not result.applied
    assert result.diff.has_changes


def test_rotate_applies_changes(mock_client):
    rotator = SecretRotator(mock_client, dry_run=False)
    result = rotator.rotate("kv/app", {"password": "new_pass"})

    mock_client.write_secret.assert_called_once()
    assert result.applied


def test_rotate_no_changes_skips_write(mock_client):
    rotator = SecretRotator(mock_client, dry_run=False)
    # Provide same value as current
    result = rotator.rotate("kv/app", {"password": "old_pass"})

    mock_client.write_secret.assert_not_called()
    assert not result.applied
    assert not result.diff.has_changes


def test_rotate_many_returns_all_results(mock_client):
    rotator = SecretRotator(mock_client, dry_run=True)
    patches = [
        {"path": "kv/app1", "data": {"password": "p1"}},
        {"path": "kv/app2", "data": {"password": "p2"}},
    ]
    results = rotator.rotate_many(patches)
    assert len(results) == 2
    assert mock_client.read_secret.call_count == 2


def test_rotate_result_path(mock_client):
    rotator = SecretRotator(mock_client, dry_run=True)
    result = rotator.rotate("kv/myservice", {"key": "value"})
    assert result.path == "kv/myservice"
