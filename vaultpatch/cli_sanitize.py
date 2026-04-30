"""CLI commands for the sanitize feature."""
from __future__ import annotations

import sys

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import from_env
from vaultpatch.sanitize import sanitize_secrets


@click.group("sanitize")
def sanitize_cmd() -> None:
    """Detect sensitive patterns in Vault secrets."""


@sanitize_cmd.command("check")
@click.argument("paths", nargs=-1, required=True)
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200", show_default=True)
@click.option("--token", envvar="VAULT_TOKEN", default=None)
@click.option("--namespace", envvar="VAULT_NAMESPACE", default=None)
@click.option("--redact", is_flag=True, default=False, help="Show redacted values in output.")
def check_cmd(paths, addr, token, namespace, redact) -> None:
    """Scan PATHS for secrets matching known sensitive patterns."""
    cfg = from_env()
    client = VaultClient(
        addr=addr or cfg.vault_addr,
        token=token or cfg.vault_token,
        namespace=namespace or cfg.namespace,
    )

    report = sanitize_secrets(client, list(paths))

    if report.error_count:
        for path, err in report.errors.items():
            click.echo(click.style(f"[ERROR] {path}: {err}", fg="red"), err=True)

    if not report.matches:
        click.echo(click.style("No sensitive patterns detected.", fg="green"))
        sys.exit(0)

    click.echo(click.style(f"Found {report.flagged_count} sensitive value(s):", fg="yellow"))
    for match in report.matches:
        value_display = match.redacted_value if redact else "<hidden>"
        click.echo(
            f"  {match.path}  [{match.key}]  pattern={match.pattern_name}  value={value_display}"
        )

    sys.exit(1)
