"""Tests for vaultpatch.archive."""
from __future__ import annotations

import gzip
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vaultpatch.archive import ArchiveReport, ArchiveResult, archive_secrets, load_archive
from vaultpatch.client import VaultClientError


@pytest.fixture()
def mock_client():
    client = MagicMock()
    client.read_secret.side_effect = lambda path: {
        "secret/app": {"API_KEY": "abc123", "DB_PASS": "hunter2"},
        "secret/svc": {"TOKEN": "tok-xyz"},
    }[path]
    return client


def test_archive_masks_values_by_default(mock_client, tmp_path):
    dest = tmp_path / "out.gz"
    report = archive_secrets(mock_client, ["secret/app"], dest, mask=True)
    assert report.success_count == 1
    assert report.error_count == 0
    result = report.results[0]
    assert result.ok
    assert all(v == "***" for v in result.data.values())


def test_archive_no_mask_stores_plaintext(mock_client, tmp_path):
    dest = tmp_path / "out.gz"
    report = archive_secrets(mock_client, ["secret/app"], dest, mask=False)
    assert report.results[0].data["API_KEY"] == "abc123"


def test_archive_records_errors(tmp_path):
    client = MagicMock()
    client.read_secret.side_effect = VaultClientError("not found")
    dest = tmp_path / "out.gz"
    report = archive_secrets(client, ["secret/missing"], dest)
    assert report.error_count == 1
    assert not report.results[0].ok
    assert "not found" in report.results[0].error


def test_archive_creates_valid_gzip_json(mock_client, tmp_path):
    dest = tmp_path / "backup.gz"
    archive_secrets(mock_client, ["secret/svc"], dest)
    assert dest.exists()
    with gzip.open(dest, "rt", encoding="utf-8") as fh:
        payload = json.load(fh)
    assert "created_at" in payload
    assert len(payload["paths"]) == 1
    assert payload["paths"][0]["path"] == "secret/svc"


def test_archive_creates_parent_dirs(mock_client, tmp_path):
    dest = tmp_path / "deep" / "nested" / "archive.gz"
    archive_secrets(mock_client, ["secret/svc"], dest)
    assert dest.exists()


def test_load_archive_round_trip(mock_client, tmp_path):
    dest = tmp_path / "round.gz"
    archive_secrets(mock_client, ["secret/app", "secret/svc"], dest, mask=False)
    payload = load_archive(dest)
    paths = [e["path"] for e in payload["paths"]]
    assert "secret/app" in paths
    assert "secret/svc" in paths


def test_archive_report_summary(mock_client, tmp_path):
    dest = tmp_path / "s.gz"
    report = archive_secrets(mock_client, ["secret/app", "secret/svc"], dest)
    summary = report.summary()
    assert "2" in summary
    assert str(dest) in summary


def test_archive_result_repr():
    r = ArchiveResult(path="secret/x", ok=True, data={"k": "***"})
    assert "secret/x" in repr(r)
