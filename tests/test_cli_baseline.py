"""CLI tests for baseline commands."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from vaultpatch.cli_baseline import baseline_cmd


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def baseline_dir(tmp_path):
    return tmp_path


def _mock_client_factory(secrets: dict):
    client = MagicMock()
    client.read_secret.side_effect = lambda p: secrets.get(p, {})
    return client


def test_capture_writes_file(runner, baseline_dir):
    out = str(baseline_dir / "baseline.json")
    client = _mock_client_factory({"secret/app": {"KEY": "val"}})
    with patch("vaultpatch.cli_baseline.from_env"), \
         patch("vaultpatch.cli_baseline.VaultClient", return_value=client):
        result = runner.invoke(baseline_cmd, ["capture", "secret/app", "--output", out])
    assert result.exit_code == 0
    assert Path(out).exists()
    data = json.loads(Path(out).read_text())
    assert data[0]["path"] == "secret/app"
    assert "KEY" in data[0]["keys"]


def test_check_no_drift_exits_zero(runner, baseline_dir):
    baseline_file = baseline_dir / "baseline.json"
    baseline_file.write_text(
        json.dumps([{"path": "secret/app", "keys": ["KEY"], "captured_at": 0.0}])
    )
    client = _mock_client_factory({"secret/app": {"KEY": "val"}})
    with patch("vaultpatch.cli_baseline.from_env"), \
         patch("vaultpatch.cli_baseline.VaultClient", return_value=client):
        result = runner.invoke(baseline_cmd, ["check", "--input", str(baseline_file)])
    assert result.exit_code == 0
    assert "OK" in result.output


def test_check_drift_reported(runner, baseline_dir):
    baseline_file = baseline_dir / "baseline.json"
    baseline_file.write_text(
        json.dumps([{"path": "secret/app", "keys": ["KEY"], "captured_at": 0.0}])
    )
    client = _mock_client_factory({"secret/app": {"KEY": "val", "NEW": "x"}})
    with patch("vaultpatch.cli_baseline.from_env"), \
         patch("vaultpatch.cli_baseline.VaultClient", return_value=client):
        result = runner.invoke(baseline_cmd, ["check", "--input", str(baseline_file)])
    assert "DRIFT" in result.output


def test_check_fail_on_drift_exits_nonzero(runner, baseline_dir):
    baseline_file = baseline_dir / "baseline.json"
    baseline_file.write_text(
        json.dumps([{"path": "secret/app", "keys": ["KEY"], "captured_at": 0.0}])
    )
    client = _mock_client_factory({"secret/app": {}})
    with patch("vaultpatch.cli_baseline.from_env"), \
         patch("vaultpatch.cli_baseline.VaultClient", return_value=client):
        result = runner.invoke(
            baseline_cmd, ["check", "--input", str(baseline_file), "--fail-on-drift"]
        )
    assert result.exit_code != 0
