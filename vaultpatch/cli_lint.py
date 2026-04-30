"""CLI commands for the lint feature."""
from __future__ import annotations

import click

from vaultpatch.client import VaultClient
from vaultpatch.config import VaultConfig
from vaultpatch.lint import lint_paths, _RULES


@click.group(name="lint")
def lint_cmd() -> None:
    """Lint secrets against configurable rules."""


@lint_cmd.command(name="check")
@click.argument("paths", nargs=-1, required=True)
@click.option(
    "--rule",
    "rules",
    multiple=True,
    help="Rule name to enforce (repeatable). Defaults to all rules.",
)
@click.option(
    "--forbidden-key",
    "forbidden_keys",
    multiple=True,
    help="Key name to forbid (repeatable).",
)
@click.option("--url", envvar="VAULT_ADDR", default="http://127.0.0.1:8200")
@click.option("--token", envvar="VAULT_TOKEN", default="root")
@click.option("--namespace", envvar="VAULT_NAMESPACE", default=None)
@click.pass_context
def check_cmd(
    ctx: click.Context,
    paths: tuple,
    rules: tuple,
    forbidden_keys: tuple,
    url: str,
    token: str,
    namespace: str,
) -> None:
    """Check one or more secret paths for lint violations."""
    cfg = VaultConfig(url=url, token=token, namespace=namespace)
    client = VaultClient(cfg)

    active_rules = list(rules) if rules else None
    report = lint_paths(
        client,
        list(paths),
        rules=active_rules,
        forbidden_keys=list(forbidden_keys) or None,
    )

    for result in report.results:
        if result.error:
            click.secho(f"  ERROR  {result.path}: {result.error}", fg="red")
        elif result.ok:
            click.secho(f"  OK     {result.path}", fg="green")
        else:
            click.secho(f"  FAIL   {result.path}", fg="yellow")
            for v in result.violations:
                click.echo(f"           [{v.rule}] {v.key}: {v.message}")

    click.echo()
    click.echo(report.summary())
    if report.violation_count or report.error_count:
        ctx.exit(1)


@lint_cmd.command(name="rules")
def rules_cmd() -> None:
    """List all available lint rule names."""
    click.echo("Available rules:")
    for name in _RULES:
        _, message = _RULES[name]
        click.echo(f"  {name:<20} {message}")
