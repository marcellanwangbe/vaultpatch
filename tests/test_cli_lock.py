"""Tests for vaultpatch.cli_lock CLI commands."""
from __future__ import annotations

import json
import time

import pytest
from click.testing import CliRunner

from vaultpatch.cli_lock import lock_cmd
from vaultpatch.lock import LockEntry, LockManager


@pytest.fixture()
def runner():
    return CliRunner()


@pytest.fixture()
def lock_dir(tmp_path):
    d = tmp_path / "locks"
    d.mkdir()
    return d


def test_list_no_locks(runner, lock_dir):
    result = runner.invoke(lock_cmd, ["list", "--lock-dir", str(lock_dir)])
    assert result.exit_code == 0
    assert "No active locks" in result.output


def test_list_shows_active_lock(runner, lock_dir):
    mgr = LockManager(lock_dir=lock_dir)
    mgr.acquire("secret/dev/api")
    result = runner.invoke(lock_cmd, ["list", "--lock-dir", str(lock_dir)])
    assert result.exit_code == 0
    assert "secret/dev/api" in result.output


def test_release_existing_lock(runner, lock_dir):
    mgr = LockManager(lock_dir=lock_dir)
    mgr.acquire("secret/prod/key")
    result = runner.invoke(lock_cmd, ["release", "secret/prod/key", "--lock-dir", str(lock_dir)])
    assert result.exit_code == 0
    assert "Released" in result.output
    assert not mgr.is_locked("secret/prod/key")


def test_release_missing_lock(runner, lock_dir):
    result = runner.invoke(lock_cmd, ["release", "secret/missing", "--lock-dir", str(lock_dir)])
    assert result.exit_code == 0
    assert "No active lock" in result.output


def test_clear_removes_expired(runner, lock_dir):
    lf = lock_dir / "secret__stale.lock"
    entry = LockEntry(path="secret/stale", pid=1, acquired_at=time.time() - 9999, ttl=1.0)
    lf.write_text(json.dumps(entry.to_dict()))
    result = runner.invoke(lock_cmd, ["clear", "--lock-dir", str(lock_dir)])
    assert result.exit_code == 0
    assert "1" in result.output


def test_check_free_path(runner, lock_dir):
    result = runner.invoke(lock_cmd, ["check", "secret/free", "--lock-dir", str(lock_dir)])
    assert "FREE" in result.output


def test_check_locked_path_exits_nonzero(runner, lock_dir):
    mgr = LockManager(lock_dir=lock_dir)
    mgr.acquire("secret/locked")
    result = runner.invoke(lock_cmd, ["check", "secret/locked", "--lock-dir", str(lock_dir)])
    assert "LOCKED" in result.output
    assert result.exit_code != 0
