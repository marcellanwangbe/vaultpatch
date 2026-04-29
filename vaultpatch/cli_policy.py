"""CLI commands for policy validation of secrets."""
from __future__ import annotations

import click

from vaultpatch.client import VaultClient, VaultClientError
from vaultpatch.config import VaultConfig
from vaultpatch.policy import SecretPolicy


@click.group("policy")
def policy_cmd() -> None:
    """Validate secrets against rotation policies."""


@policy_cmd.command("check")
@click.argument("path")
@click.option("--min-length", default=8, show_default=True, help="Minimum value length.")
@click.option("--require-uppercase", is_flag=True, default=False, help="Require uppercase letter.")
@click.option("--require-digit", is_flag=True, default=False, help="Require at least one digit.")
@click.option("--forbidden-key", "forbidden_keys", multiple=True, help="Forbidden key names.")
@click.option("--key-pattern", default=None, help="Regex pattern keys must match.")
@click.option("--token", envvar="VAULT_TOKEN", required=True, help="Vault token.")
@click.option("--addr", envvar="VAULT_ADDR", default="http://127.0.0.1:8200", help="Vault address.")
@click.option("--namespace", envvar="VAULT_NAMESPACE", default=None, help="Vault namespace.")
def check_cmd(
    path: str,
    min_length: int,
    require_uppercase: bool,
    require_digit: bool,
    forbidden_keys: tuple,
    key_pattern: str | None,
    token: str,
    addr: str,
    namespace: str | None,
) -> None:
    """Check secrets at PATH against the given policy rules."""
    config = VaultConfig(address=addr, token=token, namespace=namespace)
    client = VaultClient(config)

    try:
        secrets = client.read_secret(path)
    except VaultClientError as exc:
        raise click.ClickException(str(exc)) from exc

    if not secrets:
        raise click.ClickException(f"No secrets found at path: {path}")

    policy = SecretPolicy(
        min_length=min_length,
        require_uppercase=require_uppercase,
        require_digit=require_digit,
        forbidden_keys=list(forbidden_keys),
        key_pattern=key_pattern,
    )

    result = policy.validate(path, secrets)
    click.echo(result.summary())

    if not result.passed:
        raise SystemExit(1)
