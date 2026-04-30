"""CLI commands for secret expiration checking."""
from __future__ import annotations

import sys

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig, from_env
from vaultpatch.expire import check_expiry


@click.group("expire")
def expire_cmd() -> None:
    """Commands for checking secret expiration."""


@expire_cmd.command("check")
@click.argument("paths", nargs=-1, required=True)
@click.option("--ttl", default=90.0, show_default=True, help="TTL in days before a secret is considered expired.")
@click.option("--token", envvar="VAULT_TOKEN", default=None, help="Vault token.")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200", show_default=True)
def check_cmd(paths: tuple, ttl: float, token: str, addr: str) -> None:
    """Check whether secrets at PATHS have exceeded their TTL."""
    cfg: VaultConfig = from_env()
    if token:
        cfg.token = token
    if addr:
        cfg.address = addr

    client = VaultClient(cfg)
    report = check_expiry(client, list(paths), ttl_days=ttl)

    any_expired = False
    for result in report.results:
        if not result.ok:
            click.echo(click.style(f"  ERROR  {result.path}: {result.error}", fg="red"))
            continue
        if result.expired:
            any_expired = True
            age_str = f"{result.age_days:.1f}d" if result.age_days is not None else "unknown age"
            click.echo(click.style(f"EXPIRED  {result.path} ({age_str} > {ttl}d TTL)", fg="yellow"))
        else:
            age_str = f"{result.age_days:.1f}d" if result.age_days is not None else "no metadata"
            click.echo(click.style(f"     OK  {result.path} ({age_str})", fg="green"))

    click.echo(f"\n{report.summary()}")
    if any_expired or report.error_count:
        sys.exit(1)
