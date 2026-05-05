"""CLI commands for secret pinning: create, verify."""
from __future__ import annotations

from pathlib import Path

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig
from vaultpatch.pin import create_pin, load_pins, save_pins, verify_pins


@click.group("pin")
def pin_cmd() -> None:
    """Record and enforce expected secret fingerprints."""


@pin_cmd.command("create")
@click.argument("paths", nargs=-1, required=True)
@click.option("--pins-file", default="pins.json", show_default=True, help="Path to pins file.")
@click.option("--vault-addr", envvar="VAULT_ADDR", required=True)
@click.option("--vault-token", envvar="VAULT_TOKEN", required=True)
def create_cmd(paths: tuple, pins_file: str, vault_addr: str, vault_token: str) -> None:
    """Capture fingerprints for one or more secret PATHS."""
    cfg = VaultConfig(address=vault_addr, token=vault_token)
    client = VaultClient(cfg)
    dest = Path(pins_file)

    existing: list = []
    if dest.exists():
        existing = load_pins(dest)

    existing_paths = {p.path for p in existing}
    new_pins = list(existing)

    for path in paths:
        try:
            entry = create_pin(client, path)
            if path in existing_paths:
                new_pins = [e if e.path != path else entry for e in new_pins]
                click.echo(f"Updated pin: {path}")
            else:
                new_pins.append(entry)
                click.echo(f"Pinned: {path}")
        except Exception as exc:
            click.echo(f"ERROR {path}: {exc}", err=True)

    save_pins(new_pins, dest)
    click.echo(f"Saved {len(new_pins)} pin(s) to {pins_file}")


@pin_cmd.command("verify")
@click.option("--pins-file", default="pins.json", show_default=True, help="Path to pins file.")
@click.option("--vault-addr", envvar="VAULT_ADDR", required=True)
@click.option("--vault-token", envvar="VAULT_TOKEN", required=True)
@click.pass_context
def verify_cmd(ctx: click.Context, pins_file: str, vault_addr: str, vault_token: str) -> None:
    """Verify that pinned secrets still match their recorded fingerprints."""
    src = Path(pins_file)
    if not src.exists():
        click.echo(f"Pins file not found: {pins_file}", err=True)
        ctx.exit(1)

    cfg = VaultConfig(address=vault_addr, token=vault_token)
    client = VaultClient(cfg)
    pins = load_pins(src)
    report = verify_pins(client, pins)

    for result in report.results:
        if result.ok:
            click.echo(f"  OK       {result.path}")
        elif result.error:
            click.echo(f"  ERROR    {result.path}: {result.error}")
        else:
            click.echo(f"  MISMATCH {result.path}")
            click.echo(f"           expected: {result.expected}")
            click.echo(f"           actual:   {result.actual}")

    click.echo(report.summary())
    if report.failed_count:
        ctx.exit(1)
