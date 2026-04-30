"""Tests for vaultpatch.lock."""
from __future__ import annotations

import json
import os
import time

import pytest

from vaultpatch.lock import LockEntry, LockManager


@pytest.fixture()
def mgr(tmp_path):
    return LockManager(lock_dir=tmp_path / "locks", ttl=60.0)


def test_acquire_returns_true_when_free(mgr):
    assert mgr.acquire("secret/dev/db") is True


def test_acquire_returns_false_when_locked(mgr):
    mgr.acquire("secret/dev/db")
    assert mgr.acquire("secret/dev/db") is False


def test_release_removes_lock(mgr):
    mgr.acquire("secret/dev/db")
    mgr.release("secret/dev/db")
    assert not mgr.is_locked("secret/dev/db")


def test_release_nonexistent_is_noop(mgr):
    mgr.release("secret/does/not/exist")  # should not raise


def test_is_locked_false_when_expired(mgr, tmp_path):
    lf = mgr._lock_file("secret/old")
    lf.parent.mkdir(parents=True, exist_ok=True)
    entry = LockEntry(path="secret/old", pid=1, acquired_at=time.time() - 9999, ttl=1.0)
    lf.write_text(json.dumps(entry.to_dict()))
    assert not mgr.is_locked("secret/old")


def test_acquire_overwrites_expired_lock(mgr, tmp_path):
    lf = mgr._lock_file("secret/stale")
    lf.parent.mkdir(parents=True, exist_ok=True)
    old = LockEntry(path="secret/stale", pid=9999, acquired_at=time.time() - 9999, ttl=1.0)
    lf.write_text(json.dumps(old.to_dict()))
    assert mgr.acquire("secret/stale") is True
    new_entry = LockEntry.from_dict(json.loads(lf.read_text()))
    assert new_entry.pid == os.getpid()


def test_list_locks_returns_active(mgr):
    mgr.acquire("secret/a")
    mgr.acquire("secret/b")
    locks = mgr.list_locks()
    paths = {e.path for e in locks}
    assert "secret/a" in paths
    assert "secret/b" in paths


def test_list_locks_excludes_expired(mgr, tmp_path):
    lf = mgr._lock_file("secret/expired")
    lf.parent.mkdir(parents=True, exist_ok=True)
    old = LockEntry(path="secret/expired", pid=1, acquired_at=time.time() - 9999, ttl=1.0)
    lf.write_text(json.dumps(old.to_dict()))
    locks = mgr.list_locks()
    assert all(e.path != "secret/expired" for e in locks)


def test_clear_expired_removes_stale_files(mgr, tmp_path):
    lf = mgr._lock_file("secret/stale")
    lf.parent.mkdir(parents=True, exist_ok=True)
    old = LockEntry(path="secret/stale", pid=1, acquired_at=time.time() - 9999, ttl=1.0)
    lf.write_text(json.dumps(old.to_dict()))
    mgr.acquire("secret/active")
    removed = mgr.clear_expired()
    assert removed == 1
    assert not lf.exists()


def test_lock_entry_is_expired_false_for_fresh():
    entry = LockEntry(path="p", pid=1, acquired_at=time.time(), ttl=300.0)
    assert not entry.is_expired()


def test_lock_entry_round_trip():
    entry = LockEntry(path="secret/x", pid=42, acquired_at=1234567890.0, ttl=60.0)
    assert LockEntry.from_dict(entry.to_dict()) == entry
