"""CLI entry point for vaultpatch.

Provides commands for previewing and applying secret rotations
across HashiCorp Vault namespaces.
"""

import sys
import json
from pathlib import Path
from typing import Optional

import click

from vaultpatch.config import VaultConfig, from_file, from_env
from vaultpatch.client import VaultClient, VaultClientError
from vaultpatch.rotator import SecretRotator
from vaultpatch.diff import compute_diff


@click.group()
@click.version_option(prog_name="vaultpatch")
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=False, path_type=Path),
    default=None,
    help="Path to vaultpatch config file (YAML). Falls back to environment variables.",
)
@click.pass_context
def cli(ctx: click.Context, config: Optional[Path]) -> None:
    """vaultpatch — rotate and audit secrets across Vault namespaces."""
    ctx.ensure_object(dict)

    try:
        if config is not None:
            cfg = from_file(config)
        else:
            cfg = from_env()
    except (FileNotFoundError, KeyError, ValueError) as exc:
        raise click.ClickException(f"Configuration error: {exc}") from exc

    ctx.obj["config"] = cfg


@cli.command("diff")
@click.argument("path")
@click.argument("patch_file", type=click.Path(exists=True, path_type=Path))
@click.option("--namespace", "-n", default=None, help="Override Vault namespace.")
@click.pass_context
def diff_cmd(ctx: click.Context, path: str, patch_file: Path, namespace: Optional[str]) -> None:
    """Preview changes between current secret at PATH and PATCH_FILE (JSON).

    PATH is the Vault secret path, e.g. secret/data/myapp/config.
    PATCH_FILE is a JSON file containing the desired key/value pairs.
    """
    cfg: VaultConfig = ctx.obj["config"]
    if namespace:
        cfg = VaultConfig(
            address=cfg.address,
            token=cfg.token,
            namespace=namespace,
            extra=cfg.extra,
        )

    try:
        patch_data: dict = json.loads(patch_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"Failed to read patch file: {exc}") from exc

    try:
        client = VaultClient(cfg)
        if not client.is_authenticated():
            raise click.ClickException("Vault authentication failed. Check your token.")
        current = client.read_secret(path) or {}
    except VaultClientError as exc:
        raise click.ClickException(str(exc)) from exc

    secret_diff = compute_diff(path, current, patch_data)

    if not secret_diff.has_changes():
        click.echo(click.style("No changes detected.", fg="green"))
        return

    click.echo(click.style(f"Diff for '{path}':", bold=True))
    for line in secret_diff.summary().splitlines():
        if line.startswith("+"):
            click.echo(click.style(line, fg="green"))
        elif line.startswith("-"):
            click.echo(click.style(line, fg="red"))
        else:
            click.echo(line)


@cli.command("rotate")
@click.argument("path")
@click.argument("patch_file", type=click.Path(exists=True, path_type=Path))
@click.option("--dry-run", is_flag=True, default=False, help="Preview changes without writing.")
@click.option("--namespace", "-n", default=None, help="Override Vault namespace.")
@click.pass_context
def rotate_cmd(
    ctx: click.Context,
    path: str,
    patch_file: Path,
    dry_run: bool,
    namespace: Optional[str],
) -> None:
    """Rotate the secret at PATH using values from PATCH_FILE (JSON).

    Use --dry-run to preview without applying changes.
    """
    cfg: VaultConfig = ctx.obj["config"]
    if namespace:
        cfg = VaultConfig(
            address=cfg.address,
            token=cfg.token,
            namespace=namespace,
            extra=cfg.extra,
        )

    try:
        patch_data: dict = json.loads(patch_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        raise click.ClickException(f"Failed to read patch file: {exc}") from exc

    try:
        client = VaultClient(cfg)
        if not client.is_authenticated():
            raise click.ClickException("Vault authentication failed. Check your token.")
    except VaultClientError as exc:
        raise click.ClickException(str(exc)) from exc

    rotator = SecretRotator(client)
    result = rotator.rotate(path, patch_data, dry_run=dry_run)

    if dry_run:
        click.echo(click.style("[dry-run] ", fg="yellow", bold=True), nl=False)

    click.echo(repr(result))

    if result.diff and result.diff.has_changes():
        for line in result.diff.summary().splitlines():
            if line.startswith("+"):
                click.echo(click.style(line, fg="green"))
            elif line.startswith("-"):
                click.echo(click.style(line, fg="red"))
            else:
                click.echo(line)
    else:
        click.echo(click.style("No changes.", fg="green"))

    sys.exit(0)


def main() -> None:
    """Package entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
