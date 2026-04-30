"""CLI integration tests for the expire check command."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vaultpatch.cli_expire import expire_cmd


def _secret_with_age(days_old: float) -> dict:
    created = (datetime.now(tz=timezone.utc) - timedelta(days=days_old)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"data": {"k": "v"}, "metadata": {"created_time": created}}


@patch("vaultpatch.cli_expire.VaultClient")
@patch("vaultpatch.cli_expire.from_env")
def test_check_not_expired(mock_from_env, mock_vault_client):
    cfg = MagicMock()
    mock_from_env.return_value = cfg
    client = MagicMock()
    client.read_secret.return_value = _secret_with_age(10)
    mock_vault_client.return_value = client

    runner = CliRunner()
    result = runner.invoke(expire_cmd, ["check", "secret/young", "--ttl", "90"])
    assert result.exit_code == 0
    assert "OK" in result.output


@patch("vaultpatch.cli_expire.VaultClient")
@patch("vaultpatch.cli_expire.from_env")
def test_check_expired_exits_nonzero(mock_from_env, mock_vault_client):
    cfg = MagicMock()
    mock_from_env.return_value = cfg
    client = MagicMock()
    client.read_secret.return_value = _secret_with_age(120)
    mock_vault_client.return_value = client

    runner = CliRunner()
    result = runner.invoke(expire_cmd, ["check", "secret/old", "--ttl", "90"])
    assert result.exit_code != 0
    assert "EXPIRED" in result.output


@patch("vaultpatch.cli_expire.VaultClient")
@patch("vaultpatch.cli_expire.from_env")
def test_check_error_exits_nonzero(mock_from_env, mock_vault_client):
    cfg = MagicMock()
    mock_from_env.return_value = cfg
    client = MagicMock()
    client.read_secret.side_effect = RuntimeError("timeout")
    mock_vault_client.return_value = client

    runner = CliRunner()
    result = runner.invoke(expire_cmd, ["check", "secret/broken", "--ttl", "90"])
    assert result.exit_code != 0
    assert "ERROR" in result.output
    assert "timeout" in result.output
