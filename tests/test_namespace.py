"""Tests for vaultpatch.namespace."""
import pytest
from unittest.mock import MagicMock

from vaultpatch.client import VaultClientError
from vaultpatch.namespace import (
    NamespaceNode,
    build_namespace_tree,
    list_namespaces,
)


@pytest.fixture()
def mock_client():
    return MagicMock()


# ---------------------------------------------------------------------------
# NamespaceNode helpers
# ---------------------------------------------------------------------------

def test_namespace_node_all_paths_leaf():
    node = NamespaceNode(path="team-a")
    assert node.all_paths() == ["team-a"]


def test_namespace_node_all_paths_nested():
    root = NamespaceNode(
        path="/",
        children=[
            NamespaceNode(
                path="team-a",
                children=[NamespaceNode(path="team-a/dev")],
            ),
            NamespaceNode(path="team-b"),
        ],
    )
    assert root.all_paths() == ["/", "team-a", "team-a/dev", "team-b"]


# ---------------------------------------------------------------------------
# list_namespaces
# ---------------------------------------------------------------------------

def test_list_namespaces_root(mock_client):
    mock_client.read_secret.return_value = {"keys": ["team-a/", "team-b/"]}
    result = list_namespaces(mock_client, root="")
    assert result == ["team-a", "team-b"]
    mock_client.read_secret.assert_called_once_with("sys/namespaces")


def test_list_namespaces_with_root(mock_client):
    mock_client.read_secret.return_value = {"keys": ["dev/", "prod/"]}
    result = list_namespaces(mock_client, root="team-a")
    assert result == ["team-a/dev", "team-a/prod"]


def test_list_namespaces_returns_empty_on_error(mock_client):
    mock_client.read_secret.side_effect = VaultClientError("forbidden")
    result = list_namespaces(mock_client)
    assert result == []


def test_list_namespaces_returns_empty_when_no_keys(mock_client):
    mock_client.read_secret.return_value = {}
    result = list_namespaces(mock_client)
    assert result == []


# ---------------------------------------------------------------------------
# build_namespace_tree
# ---------------------------------------------------------------------------

def test_build_namespace_tree_flat(mock_client):
    mock_client.read_secret.return_value = {"keys": ["team-a/", "team-b/"]}
    # Second level returns nothing so recursion stops cleanly.
    mock_client.read_secret.side_effect = [
        {"keys": ["team-a/", "team-b/"]},
        {"keys": []},
        {"keys": []},
    ]
    tree = build_namespace_tree(mock_client)
    assert tree.path == "/"
    assert len(tree.children) == 2
    assert tree.children[0].path == "team-a"


def test_build_namespace_tree_respects_max_depth(mock_client):
    # Always returns a child so without max_depth it would recurse forever.
    mock_client.read_secret.return_value = {"keys": ["child/"]}
    tree = build_namespace_tree(mock_client, max_depth=2)
    # depth 0 -> root, depth 1 -> child, depth 2 -> stops
    all_paths = tree.all_paths()
    assert len(all_paths) <= 3
