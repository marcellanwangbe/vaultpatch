"""CLI commands for snapshot capture and comparison."""
from __future__ import annotations

from pathlib import Path

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig, from_env
from vaultpatch.snapshot import (
    capture_snapshot,
    diff_snapshots,
    load_snapshot,
    save_snapshot,
)


@click.group("snapshot")
def snapshot_cmd() -> None:
    """Capture and compare Vault secret snapshots."""


@snapshot_cmd.command("capture")
@click.argument("path")
@click.option("--output", "-o", required=True, type=click.Path(), help="Output JSON file")
@click.option("--token", envvar="VAULT_TOKEN", default=None)
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--namespace", envvar="VAULT_NAMESPACE", default=None)
def capture_cmd(path: str, output: str, token: str, addr: str, namespace: str) -> None:
    """Capture current secrets at PATH and save to a snapshot file."""
    cfg = VaultConfig(address=addr, token=token, namespace=namespace)
    client = VaultClient(cfg)
    snap = capture_snapshot(client, path)
    out = Path(output)
    save_snapshot(snap, out)
    click.echo(f"Snapshot saved to {out} (captured_at={snap.captured_at:.0f})")


@snapshot_cmd.command("diff")
@click.argument("before_file", type=click.Path(exists=True))
@click.argument("after_file", type=click.Path(exists=True))
@click.option("--show-values", is_flag=True, default=False, help="Unmask secret values")
def diff_cmd(before_file: str, after_file: str, show_values: bool) -> None:
    """Show diff between two snapshot files."""
    before = load_snapshot(Path(before_file))
    after = load_snapshot(Path(after_file))
    result = diff_snapshots(before, after)

    if not result.has_changes:
        click.echo("No changes detected between snapshots.")
        return

    click.echo(f"Diff for path: {result.path}")
    for key, (old_val, new_val) in result.changes.items():
        display_old = old_val if show_values else result._mask(old_val)
        display_new = new_val if show_values else result._mask(new_val)
        click.echo(f"  {key}: {display_old!r} -> {display_new!r}")
    click.echo(result.summary())
