"""CLI commands for cloning Vault secrets between paths."""

from __future__ import annotations

import click

from vaultpatch.client import VaultClient
from vaultpatch.clone import clone_secret
from vaultpatch.config import VaultConfig


@click.group("clone")
def clone_cmd() -> None:
    """Clone secrets from one path to another."""


@clone_cmd.command("run")
@click.argument("source")
@click.argument("dest")
@click.option(
    "--include",
    "include_keys",
    multiple=True,
    metavar="KEY",
    help="Only copy these keys (repeatable).",
)
@click.option(
    "--exclude",
    "exclude_keys",
    multiple=True,
    metavar="KEY",
    help="Skip these keys (repeatable).",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Preview the clone without writing.",
)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    source: str,
    dest: str,
    include_keys: tuple[str, ...],
    exclude_keys: tuple[str, ...],
    dry_run: bool,
) -> None:
    """Clone secrets from SOURCE path to DEST path."""
    cfg: VaultConfig = ctx.obj["config"]
    client = VaultClient(cfg)

    if not client.is_authenticated():
        raise click.ClickException("Vault authentication failed.")

    result = clone_secret(
        client,
        source,
        dest,
        include_keys=list(include_keys) or None,
        exclude_keys=list(exclude_keys) or None,
        dry_run=dry_run,
    )

    tag = "[DRY-RUN] " if dry_run else ""

    if not result.ok:
        raise click.ClickException(f"Clone failed: {result.error}")

    click.echo(f"{tag}{source!r} -> {dest!r}")
    if result.keys_copied:
        click.echo(f"  Copied : {', '.join(result.keys_copied)}")
    if result.keys_skipped:
        click.echo(f"  Skipped: {', '.join(result.keys_skipped)}")
    if not result.keys_copied:
        click.echo("  No keys were copied.")
