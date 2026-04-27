"""Configuration loader for vaultpatch CLI tool."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml


@dataclass
class VaultConfig:
    """Holds connection and operational settings for Vault."""

    vault_addr: str = "http://127.0.0.1:8200"
    vault_token: Optional[str] = None
    namespace: str = "root"
    mount_path: str = "secret"
    dry_run: bool = False
    audit_log: str = "vaultpatch_audit.log"
    extra: dict = field(default_factory=dict)

    @classmethod
    def from_file(cls, path: str | Path) -> "VaultConfig":
        """Load configuration from a YAML file."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_path}")

        with config_path.open("r") as fh:
            raw = yaml.safe_load(fh) or {}

        known_fields = {f for f in cls.__dataclass_fields__}
        known = {k: v for k, v in raw.items() if k in known_fields}
        extra = {k: v for k, v in raw.items() if k not in known_fields}
        return cls(**known, extra=extra)

    @classmethod
    def from_env(cls) -> "VaultConfig":
        """Override config values from environment variables."""
        return cls(
            vault_addr=os.getenv("VAULT_ADDR", "http://127.0.0.1:8200"),
            vault_token=os.getenv("VAULT_TOKEN"),
            namespace=os.getenv("VAULT_NAMESPACE", "root"),
            mount_path=os.getenv("VAULT_MOUNT", "secret"),
            dry_run=os.getenv("VAULTPATCH_DRY_RUN", "false").lower() == "true",
            audit_log=os.getenv("VAULTPATCH_AUDIT_LOG", "vaultpatch_audit.log"),
        )

    def merge_env(self) -> "VaultConfig":
        """Merge environment overrides on top of file-loaded config."""
        env = VaultConfig.from_env()
        if os.getenv("VAULT_ADDR"):
            self.vault_addr = env.vault_addr
        if os.getenv("VAULT_TOKEN"):
            self.vault_token = env.vault_token
        if os.getenv("VAULT_NAMESPACE"):
            self.namespace = env.namespace
        return self
