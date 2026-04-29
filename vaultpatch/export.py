"""Export secrets from Vault paths to structured file formats (JSON, YAML, CSV)."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

import yaml

from vaultpatch.client import VaultClient

ExportFormat = Literal["json", "yaml", "csv"]


@dataclass
class ExportReport:
    """Holds the result of a bulk export operation."""

    paths: List[str]
    secrets: Dict[str, Dict[str, str]] = field(default_factory=dict)
    errors: Dict[str, str] = field(default_factory=dict)

    @property
    def success_count(self) -> int:
        return len(self.secrets)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    def summary(self) -> str:
        return (
            f"Exported {self.success_count}/{len(self.paths)} paths "
            f"({self.error_count} errors)"
        )


def export_secrets(
    client: VaultClient,
    paths: List[str],
    mask: bool = True,
) -> ExportReport:
    """Read secrets for each path and collect into an ExportReport."""
    report = ExportReport(paths=paths)
    for path in paths:
        try:
            data = client.read_secret(path)
            if mask:
                data = {k: "***" for k in data}
            report.secrets[path] = data
        except Exception as exc:  # noqa: BLE001
            report.errors[path] = str(exc)
    return report


def render_export(report: ExportReport, fmt: ExportFormat) -> str:
    """Serialize an ExportReport to the requested format string."""
    if fmt == "json":
        return json.dumps(report.secrets, indent=2)

    if fmt == "yaml":
        return yaml.dump(report.secrets, default_flow_style=False)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["path", "key", "value"])
        for path, kv in report.secrets.items():
            for key, value in kv.items():
                writer.writerow([path, key, value])
        return buf.getvalue()

    raise ValueError(f"Unsupported export format: {fmt}")
