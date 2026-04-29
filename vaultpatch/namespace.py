"""Namespace discovery and traversal utilities for Vault."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient, VaultClientError


@dataclass
class NamespaceNode:
    """Represents a single Vault namespace with its child namespaces."""

    path: str
    children: List["NamespaceNode"] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        return f"NamespaceNode(path={self.path!r}, children={len(self.children)})"

    def all_paths(self) -> List[str]:
        """Return this path and all descendant paths in depth-first order."""
        result = [self.path]
        for child in self.children:
            result.extend(child.all_paths())
        return result


def list_namespaces(client: VaultClient, root: str = "") -> List[str]:
    """List immediate child namespaces under *root* via sys/namespaces.

    Returns an empty list when the endpoint is unavailable or the namespace
    has no children (e.g. non-enterprise Vault).
    """
    endpoint = "sys/namespaces"
    if root:
        endpoint = f"{root.rstrip('/')}/sys/namespaces"
    try:
        data = client.read_secret(endpoint)
        keys: List[str] = (data or {}).get("keys", [])
        if root:
            return [f"{root.rstrip('/')}/{k.rstrip('/')}" for k in keys]
        return [k.rstrip("/") for k in keys]
    except VaultClientError:
        return []


def build_namespace_tree(
    client: VaultClient,
    root: str = "",
    max_depth: int = 5,
    _depth: int = 0,
) -> NamespaceNode:
    """Recursively build a tree of namespaces up to *max_depth*."""
    node = NamespaceNode(path=root or "/")
    if _depth >= max_depth:
        return node
    for ns_path in list_namespaces(client, root):
        child = build_namespace_tree(
            client, root=ns_path, max_depth=max_depth, _depth=_depth + 1
        )
        node.children.append(child)
    return node
