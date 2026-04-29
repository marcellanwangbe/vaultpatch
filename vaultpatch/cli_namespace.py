"""CLI commands for namespace discovery (vaultpatch namespace ...)."""
from __future__ import annotations

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig, from_env
from vaultpatch.namespace import build_namespace_tree, NamespaceNode


def _render_tree(node: NamespaceNode, indent: int = 0) -> None:
    """Recursively print a namespace tree to stdout."""
    prefix = "  " * indent
    marker = "└─ " if indent > 0 else ""
    click.echo(f"{prefix}{marker}{node.path}")
    for child in node.children:
        _render_tree(child, indent + 1)


@click.group("namespace")
def namespace_cmd() -> None:
    """Commands for inspecting Vault namespaces."""


@namespace_cmd.command("list")
@click.option("--root", default="", show_default=True, help="Root namespace to start from.")
@click.option("--depth", default=3, show_default=True, help="Maximum traversal depth.")
@click.option("--flat", is_flag=True, default=False, help="Print flat list instead of tree.")
def list_cmd(root: str, depth: int, flat: bool) -> None:
    """List Vault namespaces starting from ROOT."""
    cfg: VaultConfig = from_env()
    client = VaultClient(cfg)

    if not client.is_authenticated():
        raise click.ClickException("Vault authentication failed. Check VAULT_TOKEN.")

    tree = build_namespace_tree(client, root=root, max_depth=depth)

    if flat:
        for path in tree.all_paths():
            click.echo(path)
    else:
        _render_tree(tree)


@namespace_cmd.command("paths")
@click.option("--root", default="", show_default=True, help="Root namespace to start from.")
@click.option("--depth", default=3, show_default=True, help="Maximum traversal depth.")
def paths_cmd(root: str, depth: int) -> None:
    """Print all namespace paths (one per line) for scripting."""
    cfg: VaultConfig = from_env()
    client = VaultClient(cfg)

    if not client.is_authenticated():
        raise click.ClickException("Vault authentication failed. Check VAULT_TOKEN.")

    tree = build_namespace_tree(client, root=root, max_depth=depth)
    for path in tree.all_paths():
        click.echo(path)
