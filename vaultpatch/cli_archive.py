"""CLI commands for archiving Vault secrets."""
from __future__ import annotations

from pathlib import Path

import click

from vaultpatch.archive import archive_secrets, load_archive
from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig


@click.group("archive")
def archive_cmd() -> None:
    """Archive and inspect Vault secret backups."""


@archive_cmd.command("run")
@click.argument("paths", nargs=-1, required=True)
@click.option("--dest", required=True, help="Destination .gz file path.")
@click.option("--no-mask", is_flag=True, default=False, help="Store plaintext values.")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--token", envvar="VAULT_TOKEN", default="root")
def run_cmd(paths: tuple, dest: str, no_mask: bool, addr: str, token: str) -> None:
    """Archive one or more secret PATHS to a compressed file."""
    cfg = VaultConfig(address=addr, token=token)
    client = VaultClient(cfg)
    report = archive_secrets(client, list(paths), Path(dest), mask=not no_mask)
    click.echo(report.summary())
    for r in report.results:
        icon = click.style("✓", fg="green") if r.ok else click.style("✗", fg="red")
        detail = "" if r.ok else f"  [{r.error}]"
        click.echo(f"  {icon} {r.path}{detail}")
    if report.error_count:
        raise SystemExit(1)


@archive_cmd.command("inspect")
@click.argument("src")
@click.option("--show-data", is_flag=True, default=False, help="Print stored data.")
def inspect_cmd(src: str, show_data: bool) -> None:
    """Inspect a previously created archive file."""
    payload = load_archive(Path(src))
    click.echo(f"Created at : {payload.get('created_at')}")
    entries = payload.get("paths", [])
    click.echo(f"Entries    : {len(entries)}")
    for entry in entries:
        icon = click.style("✓", fg="green") if entry["ok"] else click.style("✗", fg="red")
        click.echo(f"  {icon} {entry['path']}")
        if show_data and entry.get("data"):
            for k, v in entry["data"].items():
                click.echo(f"       {k}: {v}")
