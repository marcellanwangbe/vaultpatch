"""Tests for vaultpatch.diff."""

import pytest

from vaultpatch.diff import SecretDiff, _mask, compute_diff


# ---------------------------------------------------------------------------
# _mask
# ---------------------------------------------------------------------------

def test_mask_short_value():
    assert _mask("abc") == "***"


def test_mask_long_value():
    result = _mask("supersecret", visible=4)
    assert result.startswith("supe")
    assert "*" in result
    assert "supersecret" not in result


# ---------------------------------------------------------------------------
# compute_diff
# ---------------------------------------------------------------------------

def test_compute_diff_added_key():
    diff = compute_diff("kv/app", {"a": "1"}, {"a": "1", "b": "2"})
    assert "b" in diff.added
    assert not diff.removed
    assert not diff.changed
    assert diff.has_changes


def test_compute_diff_removed_key():
    diff = compute_diff("kv/app", {"a": "1", "b": "2"}, {"a": "1"})
    assert "b" in diff.removed
    assert diff.has_changes


def test_compute_diff_changed_key():
    diff = compute_diff("kv/app", {"pw": "old"}, {"pw": "new"})
    assert "pw" in diff.changed
    assert diff.changed["pw"] == ("old", "new")
    assert diff.has_changes


def test_compute_diff_unchanged():
    diff = compute_diff("kv/app", {"a": "1"}, {"a": "1"})
    assert "a" in diff.unchanged
    assert not diff.has_changes


def test_summary_contains_path():
    diff = compute_diff("kv/myapp", {"x": "old"}, {"x": "new"})
    summary = diff.summary()
    assert "kv/myapp" in summary


def test_summary_no_changes_label():
    diff = compute_diff("kv/myapp", {"x": "1"}, {"x": "1"})
    assert "no changes" in diff.summary()
