"""Tests for vaultpatch.config module."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from vaultpatch.config import VaultConfig


@pytest.fixture()
def config_file(tmp_path: Path) -> Path:
    """Write a minimal YAML config file and return its path."""
    data = {
        "vault_addr": "https://vault.example.com",
        "namespace": "engineering",
        "mount_path": "kv",
        "dry_run": True,
        "audit_log": "my_audit.log",
        "unknown_key": "should_be_extra",
    }
    cfg = tmp_path / "vaultpatch.yaml"
    cfg.write_text(yaml.dump(data))
    return cfg


def test_from_file_loads_known_fields(config_file: Path) -> None:
    cfg = VaultConfig.from_file(config_file)
    assert cfg.vault_addr == "https://vault.example.com"
    assert cfg.namespace == "engineering"
    assert cfg.mount_path == "kv"
    assert cfg.dry_run is True
    assert cfg.audit_log == "my_audit.log"


def test_from_file_stores_unknown_as_extra(config_file: Path) -> None:
    cfg = VaultConfig.from_file(config_file)
    assert cfg.extra == {"unknown_key": "should_be_extra"}


def test_from_file_missing_raises(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        VaultConfig.from_file(tmp_path / "nonexistent.yaml")


def test_from_env_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_ADDR", "https://env-vault.example.com")
    monkeypatch.setenv("VAULT_TOKEN", "s.testtoken")
    monkeypatch.setenv("VAULT_NAMESPACE", "ops")
    monkeypatch.setenv("VAULT_MOUNT", "kvv2")
    monkeypatch.setenv("VAULTPATCH_DRY_RUN", "true")
    monkeypatch.setenv("VAULTPATCH_AUDIT_LOG", "env_audit.log")

    cfg = VaultConfig.from_env()
    assert cfg.vault_addr == "https://env-vault.example.com"
    assert cfg.vault_token == "s.testtoken"
    assert cfg.namespace == "ops"
    assert cfg.mount_path == "kvv2"
    assert cfg.dry_run is True
    assert cfg.audit_log == "env_audit.log"


def test_merge_env_overrides_token(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VAULT_TOKEN", "s.overridden")
    cfg = VaultConfig.from_file(config_file)
    cfg.merge_env()
    assert cfg.vault_token == "s.overridden"


def test_defaults_without_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("VAULT_ADDR", "VAULT_TOKEN", "VAULT_NAMESPACE", "VAULT_MOUNT",
                "VAULTPATCH_DRY_RUN", "VAULTPATCH_AUDIT_LOG"):
        monkeypatch.delenv(var, raising=False)

    cfg = VaultConfig.from_env()
    assert cfg.vault_addr == "http://127.0.0.1:8200"
    assert cfg.vault_token is None
    assert cfg.dry_run is False
