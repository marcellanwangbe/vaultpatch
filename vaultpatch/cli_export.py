"""CLI commands for exporting Vault secrets to file formats."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig
from vaultpatch.export import ExportFormat, export_secrets, render_export


@click.group("export")
def export_cmd() -> None:
    """Export secrets from Vault paths to structured formats."""


@export_cmd.command("run")
@click.argument("paths", nargs=-1, required=True)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["json", "yaml", "csv"]),
    default="json",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--no-mask",
    is_flag=True,
    default=False,
    help="Include plaintext secret values (use with caution).",
)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    paths: tuple[str, ...],
    fmt: ExportFormat,
    output: Optional[str],
    no_mask: bool,
) -> None:
    """Export secrets at PATHS to the chosen format."""
    cfg: VaultConfig = ctx.obj["config"]
    client = VaultClient(cfg)

    report = export_secrets(client, list(paths), mask=not no_mask)

    if report.error_count:
        for path, err in report.errors.items():
            click.echo(f"[error] {path}: {err}", err=True)

    rendered = render_export(report, fmt)

    if output:
        dest = Path(output)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rendered)
        click.echo(f"Exported {report.success_count} paths to {dest}")
    else:
        click.echo(rendered)

    click.echo(report.summary(), err=True)
    if report.error_count:
        sys.exit(1)
