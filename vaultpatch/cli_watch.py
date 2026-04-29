"""CLI commands for the watch/drift-detection feature."""
from __future__ import annotations

import json
import sys
import time

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig
from vaultpatch.snapshot import load_snapshot
from vaultpatch.watch import watch_once, watch_loop, WatchReport


@click.group("watch")
def watch_cmd():
    """Watch secrets for drift against a saved snapshot."""


def _print_report(report: WatchReport, json_output: bool) -> None:
    if json_output:
        data = {
            "paths_checked": report.paths_checked,
            "drift_count": report.drift_count,
            "elapsed_seconds": round(report.elapsed_seconds, 4),
            "events": [
                {"path": e.path, "changes": e.diff.summary(), "detected_at": e.detected_at}
                for e in report.events
            ],
        }
        click.echo(json.dumps(data, indent=2))
    else:
        click.echo(report.summary())
        for event in report.events:
            click.echo(f"  DRIFT  {event.path}: {event.diff.summary()}")


@watch_cmd.command("once")
@click.argument("snapshot_file")
@click.option("--path", "paths", multiple=True, help="Limit to specific secret paths.")
@click.option("--json", "json_output", is_flag=True, default=False)
@click.pass_context
def once_cmd(ctx, snapshot_file: str, paths, json_output: bool):
    """Run a single drift check against SNAPSHOT_FILE."""
    cfg: VaultConfig = ctx.obj["config"]
    client = VaultClient(cfg)
    snapshot = load_snapshot(snapshot_file)
    report = watch_once(client, snapshot, list(paths) or None)
    _print_report(report, json_output)
    if report.drift_count > 0:
        sys.exit(1)


@watch_cmd.command("loop")
@click.argument("snapshot_file")
@click.option("--interval", default=30.0, show_default=True, help="Poll interval in seconds.")
@click.option("--json", "json_output", is_flag=True, default=False)
@click.pass_context
def loop_cmd(ctx, snapshot_file: str, interval: float, json_output: bool):
    """Continuously watch for drift, printing a report each cycle."""
    cfg: VaultConfig = ctx.obj["config"]
    client = VaultClient(cfg)
    snapshot = load_snapshot(snapshot_file)

    def on_drift(report: WatchReport):
        _print_report(report, json_output)

    click.echo(f"Watching secrets every {interval}s. Press Ctrl+C to stop.")
    try:
        watch_loop(client, snapshot, interval=interval, on_drift=on_drift)
    except KeyboardInterrupt:
        click.echo("\nWatch stopped.")
