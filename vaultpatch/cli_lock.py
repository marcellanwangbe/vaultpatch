"""CLI commands for managing secret path locks."""
from __future__ import annotations

import click

from vaultpatch.lock import LockManager


@click.group("lock")
def lock_cmd():
    """Manage path locks to prevent concurrent rotations."""


@lock_cmd.command("list")
@click.option("--lock-dir", default=None, help="Custom lock directory.")
def list_cmd(lock_dir):
    """List all active (non-expired) locks."""
    mgr = LockManager(**({"lock_dir": lock_dir} if lock_dir else {}))
    locks = mgr.list_locks()
    if not locks:
        click.echo("No active locks.")
        return
    click.echo(f"{'PATH':<40} {'PID':>8}  {'ACQUIRED':>20}  {'TTL':>8}")
    click.echo("-" * 82)
    import datetime
    for entry in locks:
        ts = datetime.datetime.fromtimestamp(entry.acquired_at).strftime("%Y-%m-%d %H:%M:%S")
        click.echo(f"{entry.path:<40} {entry.pid:>8}  {ts:>20}  {entry.ttl:>8.0f}s")


@lock_cmd.command("release")
@click.argument("path")
@click.option("--lock-dir", default=None, help="Custom lock directory.")
def release_cmd(path, lock_dir):
    """Force-release a lock on PATH."""
    mgr = LockManager(**({"lock_dir": lock_dir} if lock_dir else {}))
    if not mgr.is_locked(path):
        click.echo(f"No active lock for: {path}")
        return
    mgr.release(path)
    click.echo(f"Released lock: {path}")


@lock_cmd.command("clear")
@click.option("--lock-dir", default=None, help="Custom lock directory.")
def clear_cmd(lock_dir):
    """Remove all expired lock files."""
    mgr = LockManager(**({"lock_dir": lock_dir} if lock_dir else {}))
    removed = mgr.clear_expired()
    click.echo(f"Cleared {removed} expired lock(s).")


@lock_cmd.command("check")
@click.argument("path")
@click.option("--lock-dir", default=None, help="Custom lock directory.")
def check_cmd(path, lock_dir):
    """Check whether PATH is currently locked."""
    mgr = LockManager(**({"lock_dir": lock_dir} if lock_dir else {}))
    if mgr.is_locked(path):
        click.echo(f"LOCKED: {path}")
        raise SystemExit(1)
    click.echo(f"FREE: {path}")
