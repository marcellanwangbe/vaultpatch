"""CLI commands for quota enforcement."""
from __future__ import annotations

import sys

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig
from vaultpatch.quota import check_quota


@click.group("quota")
def quota_cmd() -> None:
    """Enforce key/value count and size quotas on secret paths."""


@quota_cmd.command("check")
@click.argument("paths", nargs=-1, required=True)
@click.option("--max-keys", default=20, show_default=True, help="Max allowed keys per path.")
@click.option("--max-bytes", default=4096, show_default=True, help="Max total value bytes per path.")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--token", envvar="VAULT_TOKEN", default="root")
def check_cmd(
    paths: tuple[str, ...],
    max_keys: int,
    max_bytes: int,
    addr: str,
    token: str,
) -> None:
    """Check PATHS against quota limits and exit non-zero on violations."""
    cfg = VaultConfig(address=addr, token=token)
    client = VaultClient(cfg)
    report = check_quota(client, list(paths), max_keys=max_keys, max_bytes=max_bytes)

    if report.errors:
        for err in report.errors:
            click.echo(f"[error] {err}", err=True)

    if report.ok:
        click.echo(f"All {len(paths)} path(s) within quota.")
        return

    for v in report.violations:
        reasons = []
        if v.exceeds_keys:
            reasons.append(f"keys {v.key_count} > {v.max_keys}")
        if v.exceeds_bytes:
            reasons.append(f"bytes {v.value_bytes} > {v.max_bytes}")
        click.echo(f"[violation] {v.path}: {', '.join(reasons)}")

    click.echo(report.summary())
    sys.exit(1)
