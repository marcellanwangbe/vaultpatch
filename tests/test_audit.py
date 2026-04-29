"""Tests for the audit logging module."""

import json
from pathlib import Path

import pytest

from vaultpatch.audit import AuditEntry, AuditLogger
from vaultpatch.diff import SecretDiff
from vaultpatch.rotator import RotationResult


def _make_result(
    path="secret/myapp",
    namespace="ns1",
    success=True,
    error=None,
    added=None,
    removed=None,
    changed=None,
) -> RotationResult:
    diff = SecretDiff(
        path=path,
        added=added or {},
        removed=removed or {},
        changed=changed or {},
    )
    return RotationResult(
        path=path,
        namespace=namespace,
        diff=diff,
        success=success,
        error=error,
    )


def test_audit_entry_from_rotation_result():
    result = _make_result(changed={"API_KEY": ("old", "new")}, added={"TOKEN": "abc"})
    entry = AuditEntry.from_rotation_result(result, dry_run=False)

    assert entry.path == "secret/myapp"
    assert entry.namespace == "ns1"
    assert "API_KEY" in entry.changed_keys
    assert "TOKEN" in entry.added_keys
    assert entry.removed_keys == []
    assert entry.dry_run is False
    assert entry.success is True
    assert entry.error is None


def test_audit_entry_dry_run_flag():
    result = _make_result()
    entry = AuditEntry.from_rotation_result(result, dry_run=True)
    assert entry.dry_run is True


def test_audit_logger_writes_jsonl(tmp_path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)
    result = _make_result(changed={"SECRET": ("v1", "v2")})
    logger.record_result(result)

    lines = log_file.read_text().strip().splitlines()
    assert len(lines) == 1
    data = json.loads(lines[0])
    assert data["path"] == "secret/myapp"
    assert "SECRET" in data["changed_keys"]


def test_audit_logger_appends_multiple(tmp_path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)
    logger.record_result(_make_result(path="secret/a"))
    logger.record_result(_make_result(path="secret/b"))

    entries = logger.read_all()
    assert len(entries) == 2
    assert entries[0].path == "secret/a"
    assert entries[1].path == "secret/b"


def test_audit_logger_read_all_empty(tmp_path):
    logger = AuditLogger(tmp_path / "missing.log")
    assert logger.read_all() == []


def test_audit_logger_creates_parent_dirs(tmp_path):
    log_file = tmp_path / "nested" / "dir" / "audit.log"
    logger = AuditLogger(log_file)
    logger.record_result(_make_result())
    assert log_file.exists()
