"""CLI commands for inspecting the audit log."""

from __future__ import annotations

import json
from typing import Optional

import click

from vaultpatch.audit import AuditLogger


@click.group("audit")
def audit_cmd() -> None:
    """Inspect the vaultpatch rotation audit log."""


@audit_cmd.command("show")
@click.option(
    "--log",
    "log_path",
    default="vaultpatch-audit.log",
    show_default=True,
    help="Path to the audit log file.",
)
@click.option(
    "--path",
    "filter_path",
    default=None,
    help="Filter entries by secret path substring.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False, help="Output raw JSON lines."
)
def show_cmd(log_path: str, filter_path: Optional[str], as_json: bool) -> None:
    """Display rotation audit entries."""
    logger = AuditLogger(log_path)
    entries = logger.read_all()

    if filter_path:
        entries = [e for e in entries if filter_path in e.path]

    if not entries:
        click.echo("No audit entries found.")
        return

    for entry in entries:
        if as_json:
            click.echo(json.dumps(entry.to_dict()))
        else:
            status = click.style("OK", fg="green") if entry.success else click.style("FAIL", fg="red")
            dry = click.style(" [dry-run]", fg="yellow") if entry.dry_run else ""
            click.echo(
                f"[{entry.timestamp}] {status}{dry} {entry.path}"
                f" (ns={entry.namespace or '-'})"
                f" +{len(entry.added_keys)} ~{len(entry.changed_keys)} -{len(entry.removed_keys)}"
            )
            if entry.error:
                click.echo(f"  error: {entry.error}")


@audit_cmd.command("clear")
@click.option(
    "--log",
    "log_path",
    default="vaultpatch-audit.log",
    show_default=True,
    help="Path to the audit log file.",
)
@click.confirmation_option(prompt="Are you sure you want to clear the audit log?")
def clear_cmd(log_path: str) -> None:
    """Erase all entries from the audit log."""
    from pathlib import Path

    p = Path(log_path)
    if p.exists():
        p.write_text("")
        click.echo(f"Audit log cleared: {log_path}")
    else:
        click.echo("Audit log not found; nothing to clear.")
