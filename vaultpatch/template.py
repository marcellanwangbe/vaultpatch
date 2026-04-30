"""Template rendering for Vault secret values using variable substitution."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TemplateError:
    key: str
    message: str

    def __str__(self) -> str:
        return f"[{self.key}] {self.message}"


@dataclass
class TemplateResult:
    path: str
    rendered: Dict[str, str] = field(default_factory=dict)
    errors: List[TemplateError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return len(self.errors) == 0

    def summary(self) -> str:
        if self.ok:
            return f"{self.path}: {len(self.rendered)} key(s) rendered successfully"
        return (
            f"{self.path}: {len(self.rendered)} rendered, "
            f"{len(self.errors)} error(s)"
        )


_PLACEHOLDER_RE = re.compile(r"\{\{\s*([\w.]+)\s*\}\}")


def render_value(template: str, variables: Dict[str, str]) -> str:
    """Replace {{var}} placeholders with values from *variables*."""
    def _replace(match: re.Match) -> str:
        name = match.group(1)
        if name not in variables:
            raise KeyError(name)
        return variables[name]

    return _PLACEHOLDER_RE.sub(_replace, template)


def render_secret(
    path: str,
    secret: Dict[str, str],
    variables: Dict[str, str],
    keys: Optional[List[str]] = None,
) -> TemplateResult:
    """Render template placeholders in *secret* values.

    Args:
        path: Vault path (used for reporting only).
        secret: Mapping of secret keys to (possibly templated) values.
        variables: Variable substitution context.
        keys: If given, only render these keys; others are passed through.

    Returns:
        A :class:`TemplateResult` with rendered values and any errors.
    """
    result = TemplateResult(path=path)
    for key, value in secret.items():
        if keys is not None and key not in keys:
            result.rendered[key] = value
            continue
        try:
            result.rendered[key] = render_value(value, variables)
        except KeyError as exc:
            missing = exc.args[0]
            result.errors.append(
                TemplateError(key=key, message=f"undefined variable '{missing}'")
            )
    return result
