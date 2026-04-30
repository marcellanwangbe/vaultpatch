"""Main CLI entry-point for vaultpatch."""
from __future__ import annotations

import click

from vaultpatch.client import VaultClient, VaultClientError
from vaultpatch.config import VaultConfig, from_env
from vaultpatch.diff import compute_diff
from vaultpatch.rotator import SecretRotator
from vaultpatch.cli_audit import audit_cmd
from vaultpatch.cli_namespace import namespace_cmd
from vaultpatch.cli_policy import policy_cmd
from vaultpatch.cli_snapshot import snapshot_cmd
from vaultpatch.cli_export import export_cmd
from vaultpatch.cli_watch import watch_cmd
from vaultpatch.cli_clone import clone_cmd
from vaultpatch.cli_lock import lock_cmd


@click.group()
def cli():
    """vaultpatch — rotate and audit Vault secrets safely."""


@cli.command("diff")
@click.argument("path")
@click.option("--token", envvar="VAULT_TOKEN", required=True)
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--new-values", "-n", multiple=True, help="key=value pairs for proposed secrets.")
def diff_cmd(path, token, addr, new_values):
    """Preview changes for a secret path without applying them."""
    proposed: dict = {}
    for kv in new_values:
        if "=" not in kv:
            raise click.BadParameter(f"Expected key=value, got: {kv}")
        k, v = kv.split("=", 1)
        proposed[k] = v

    client = VaultClient(addr=addr, token=token)
    try:
        current = client.read_secret(path) or {}
    except VaultClientError as exc:
        raise click.ClickException(str(exc)) from exc

    diff = compute_diff(path, current, proposed)
    if not diff.has_changes():
        click.echo("No changes detected.")
        return
    click.echo(diff.summary())


@cli.command("rotate")
@click.argument("path")
@click.option("--token", envvar="VAULT_TOKEN", required=True)
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--new-values", "-n", multiple=True, help="key=value pairs to write.")
@click.option("--dry-run", is_flag=True, default=False)
def rotate_cmd(path, token, addr, new_values, dry_run):
    """Rotate secrets at PATH."""
    proposed: dict = {}
    for kv in new_values:
        if "=" not in kv:
            raise click.BadParameter(f"Expected key=value, got: {kv}")
        k, v = kv.split("=", 1)
        proposed[k] = v

    client = VaultClient(addr=addr, token=token)
    rotator = SecretRotator(client=client, dry_run=dry_run)
    try:
        result = rotator.rotate(path, proposed)
    except VaultClientError as exc:
        raise click.ClickException(str(exc)) from exc

    status = "[DRY RUN] " if dry_run else ""
    if result.skipped:
        click.echo(f"{status}No changes for {path}.")
    else:
        click.echo(f"{status}Rotated {path}: {result.diff.summary()}")


def main():
    cli.add_command(audit_cmd, name="audit")
    cli.add_command(namespace_cmd, name="namespace")
    cli.add_command(policy_cmd, name="policy")
    cli.add_command(snapshot_cmd, name="snapshot")
    cli.add_command(export_cmd, name="export")
    cli.add_command(watch_cmd, name="watch")
    cli.add_command(clone_cmd, name="clone")
    cli.add_command(lock_cmd, name="lock")
    cli()


if __name__ == "__main__":
    main()
