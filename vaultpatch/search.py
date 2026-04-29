"""Search secrets across Vault paths by key or value pattern."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from vaultpatch.client import VaultClient


@dataclass
class SearchMatch:
    path: str
    key: str
    masked_value: str

    def __repr__(self) -> str:
        return f"SearchMatch(path={self.path!r}, key={self.key!r})"


@dataclass
class SearchReport:
    pattern: str
    search_keys: bool
    search_values: bool
    matches: List[SearchMatch] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.matches)

    def summary(self) -> str:
        return (
            f"Pattern '{self.pattern}' matched {self.total} secret(s) "
            f"across {len({m.path for m in self.matches})} path(s)."
        )


def _mask_value(value: str) -> str:
    if len(value) <= 4:
        return "****"
    return value[:2] + "****" + value[-2:]


def search_secrets(
    client: VaultClient,
    paths: List[str],
    pattern: str,
    *,
    search_keys: bool = True,
    search_values: bool = False,
    case_sensitive: bool = False,
) -> SearchReport:
    """Search for a regex pattern in secret keys and/or values across paths."""
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = re.compile(pattern, flags)
    report = SearchReport(
        pattern=pattern,
        search_keys=search_keys,
        search_values=search_values,
    )

    for path in paths:
        try:
            secrets = client.read_secret(path)
        except Exception:
            continue
        if not secrets:
            continue
        for key, value in secrets.items():
            str_value = str(value)
            matched = False
            if search_keys and compiled.search(key):
                matched = True
            if not matched and search_values and compiled.search(str_value):
                matched = True
            if matched:
                report.matches.append(
                    SearchMatch(
                        path=path,
                        key=key,
                        masked_value=_mask_value(str_value),
                    )
                )

    return report
