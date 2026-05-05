"""CLI tests for the quota check command."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from vaultpatch.cli_quota import quota_cmd
from vaultpatch.quota import QuotaReport, QuotaViolation


@patch("vaultpatch.cli_quota.VaultClient")
@patch("vaultpatch.cli_quota.check_quota")
def test_check_no_violations(mock_check, mock_client_cls):
    mock_check.return_value = QuotaReport()
    runner = CliRunner()
    result = runner.invoke(quota_cmd, ["check", "secret/a", "secret/b"])
    assert result.exit_code == 0
    assert "within quota" in result.output


@patch("vaultpatch.cli_quota.VaultClient")
@patch("vaultpatch.cli_quota.check_quota")
def test_check_with_violations_exits_nonzero(mock_check, mock_client_cls):
    report = QuotaReport(
        violations=[
            QuotaViolation(
                path="secret/big",
                key_count=25,
                max_keys=20,
                value_bytes=100,
                max_bytes=4096,
            )
        ]
    )
    mock_check.return_value = report
    runner = CliRunner()
    result = runner.invoke(quota_cmd, ["check", "secret/big"])
    assert result.exit_code == 1
    assert "violation" in result.output
    assert "secret/big" in result.output


@patch("vaultpatch.cli_quota.VaultClient")
@patch("vaultpatch.cli_quota.check_quota")
def test_check_errors_printed_to_stderr(mock_check, mock_client_cls):
    report = QuotaReport(errors=["secret/missing: not found"])
    mock_check.return_value = report
    runner = CliRunner(mix_stderr=False)
    result = runner.invoke(quota_cmd, ["check", "secret/missing"])
    assert "not found" in result.output or "not found" in (result.stderr or "")


@patch("vaultpatch.cli_quota.VaultClient")
@patch("vaultpatch.cli_quota.check_quota")
def test_check_passes_custom_limits(mock_check, mock_client_cls):
    mock_check.return_value = QuotaReport()
    runner = CliRunner()
    runner.invoke(
        quota_cmd,
        ["check", "secret/a", "--max-keys", "5", "--max-bytes", "512"],
    )
    _, kwargs = mock_check.call_args
    assert kwargs["max_keys"] == 5
    assert kwargs["max_bytes"] == 512
