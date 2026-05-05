"""CLI commands for baseline capture and drift detection."""
from __future__ import annotations

from pathlib import Path

import click

from vaultpatch.baseline import (
    capture_baseline,
    compare_baseline,
    load_baseline,
    save_baseline,
)
from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig, from_env


@click.group("baseline")
def baseline_cmd() -> None:
    """Capture and compare secret key baselines."""


@baseline_cmd.command("capture")
@click.argument("paths", nargs=-1, required=True)
@click.option("--output", "-o", default=".vaultpatch/baseline.json", show_default=True)
def capture_cmd(paths: tuple, output: str) -> None:
    """Capture a baseline snapshot of key names for PATHS."""
    cfg: VaultConfig = from_env()
    client = VaultClient(cfg)
    entries = capture_baseline(client, list(paths))
    dest = Path(output)
    save_baseline(entries, dest)
    click.echo(f"Baseline saved to {dest} ({len(entries)} path(s))")


@baseline_cmd.command("check")
@click.option("--input", "-i", "src", default=".vaultpatch/baseline.json", show_default=True)
@click.option("--fail-on-drift", is_flag=True, default=False)
def check_cmd(src: str, fail_on_drift: bool) -> None:
    """Compare live secrets against a saved baseline."""
    cfg: VaultConfig = from_env()
    client = VaultClient(cfg)
    entries = load_baseline(Path(src))
    drifts = compare_baseline(client, entries)

    drifted = [d for d in drifts if d.has_drift]
    for d in drifts:
        marker = "DRIFT" if d.has_drift else "OK"
        click.echo(f"[{marker}] {d.summary()}")

    if drifted:
        click.echo(f"\n{len(drifted)} path(s) have drifted from baseline.")
        if fail_on_drift:
            raise SystemExit(1)
    else:
        click.echo("\nAll paths match baseline.")
