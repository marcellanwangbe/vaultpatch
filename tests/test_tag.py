"""Tests for vaultpatch.tag."""
import pytest
from unittest.mock import MagicMock

from vaultpatch.tag import TaggedPath, TagReport, tag_paths


@pytest.fixture()
def mock_client():
    return MagicMock()


# ---------------------------------------------------------------------------
# TaggedPath
# ---------------------------------------------------------------------------

def test_tagged_path_has_tag_true():
    tp = TaggedPath(path="secret/db", tags=["prod", "database"])
    assert tp.has_tag("prod") is True


def test_tagged_path_has_tag_case_insensitive():
    tp = TaggedPath(path="secret/db", tags=["PROD"])
    assert tp.has_tag("prod") is True


def test_tagged_path_has_tag_false():
    tp = TaggedPath(path="secret/db", tags=["staging"])
    assert tp.has_tag("prod") is False


# ---------------------------------------------------------------------------
# TagReport
# ---------------------------------------------------------------------------

def test_tag_report_counts():
    report = TagReport(
        matched=[TaggedPath("a"), TaggedPath("b")],
        skipped=["c"],
    )
    assert report.matched_count == 2
    assert report.skipped_count == 1


def test_tag_report_summary():
    report = TagReport(
        matched=[TaggedPath("a")],
        skipped=["b", "c"],
    )
    assert "1 matched" in report.summary()
    assert "2 skipped" in report.summary()


# ---------------------------------------------------------------------------
# tag_paths
# ---------------------------------------------------------------------------

def test_tag_paths_no_filter(mock_client):
    paths = ["secret/app/db", "secret/app/cache", "secret/infra/k8s"]
    tag_map = {"secret/app": ["app"], "secret/infra": ["infra"]}
    report = tag_paths(mock_client, paths, tag_map)
    assert report.matched_count == 3
    assert report.skipped_count == 0


def test_tag_paths_with_filter_keeps_matching(mock_client):
    paths = ["secret/app/db", "secret/infra/k8s"]
    tag_map = {"secret/app": ["app"], "secret/infra": ["infra"]}
    report = tag_paths(mock_client, paths, tag_map, filter_tag="app")
    assert report.matched_count == 1
    assert report.matched[0].path == "secret/app/db"
    assert report.skipped == ["secret/infra/k8s"]


def test_tag_paths_exact_match(mock_client):
    paths = ["secret/exact"]
    tag_map = {"secret/exact": ["special"]}
    report = tag_paths(mock_client, paths, tag_map, filter_tag="special")
    assert report.matched_count == 1
    assert report.matched[0].has_tag("special")


def test_tag_paths_no_matching_prefix_gives_empty_tags(mock_client):
    paths = ["secret/unknown"]
    tag_map = {"secret/app": ["app"]}
    report = tag_paths(mock_client, paths, tag_map)
    assert report.matched[0].tags == []


def test_tag_paths_deduplicates_tags(mock_client):
    paths = ["secret/app/db"]
    tag_map = {
        "secret/app": ["prod", "app"],
        "secret/app/db": ["prod"],  # 'prod' would appear twice without dedup
    }
    report = tag_paths(mock_client, paths, tag_map)
    tags = report.matched[0].tags
    assert tags.count("prod") == 1
