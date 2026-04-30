"""Tests for vaultpatch.export module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest
import yaml

from vaultpatch.export import ExportReport, export_secrets, render_export


@pytest.fixture()
def mock_client() -> MagicMock:
    client = MagicMock()
    client.read_secret.side_effect = lambda path: {
        "secret/a": {"user": "alice", "pass": "s3cr3t"},
        "secret/b": {"token": "abc123"},
    }[path]
    return client


def test_export_masks_values_by_default(mock_client):
    report = export_secrets(mock_client, ["secret/a"])
    assert report.secrets["secret/a"] == {"user": "***", "pass": "***"}


def test_export_no_mask_returns_plaintext(mock_client):
    report = export_secrets(mock_client, ["secret/a"], mask=False)
    assert report.secrets["secret/a"]["user"] == "alice"


def test_export_records_errors():
    client = MagicMock()
    client.read_secret.side_effect = RuntimeError("permission denied")
    report = export_secrets(client, ["secret/x"])
    assert "secret/x" in report.errors
    assert report.error_count == 1
    assert report.success_count == 0


def test_export_summary_string(mock_client):
    report = export_secrets(mock_client, ["secret/a", "secret/b"])
    assert "2/2" in report.summary()
    assert "0 errors" in report.summary()


def test_export_mixed_success_and_errors(mock_client):
    """Ensure summary reflects partial failures when some paths error out."""
    client = MagicMock()
    client.read_secret.side_effect = lambda path: (
        {"user": "alice"} if path == "secret/a" else (_ for _ in ()).throw(RuntimeError("denied"))
    )
    report = export_secrets(client, ["secret/a", "secret/bad"])
    assert report.success_count == 1
    assert report.error_count == 1
    assert "secret/bad" in report.errors
    assert "1/2" in report.summary()


def test_render_json(mock_client):
    report = export_secrets(mock_client, ["secret/a"], mask=False)
    rendered = render_export(report, "json")
    parsed = json.loads(rendered)
    assert parsed["secret/a"]["user"] == "alice"


def test_render_yaml(mock_client):
    report = export_secrets(mock_client, ["secret/b"], mask=False)
    rendered = render_export(report, "yaml")
    parsed = yaml.safe_load(rendered)
    assert parsed["secret/b"]["token"] == "abc123"


def test_render_csv(mock_client):
    report = export_secrets(mock_client, ["secret/b"], mask=False)
    rendered = render_export(report, "csv")
    lines = rendered.strip().splitlines()
    assert lines[0] == "path,key,value"
    assert any("secret/b" in line for line in lines[1:])


def test_render_unsupported_format():
    report = ExportReport(paths=[])
    with pytest.raises(ValueError, match="Unsupported export format"):
        render_export(report, "xml")  # type: ignore[arg-type]
