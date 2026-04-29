"""Tag-based filtering and labeling for Vault secret paths."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vaultpatch.client import VaultClient


@dataclass
class TaggedPath:
    """A secret path decorated with a set of string tags."""

    path: str
    tags: List[str] = field(default_factory=list)

    def __repr__(self) -> str:  # pragma: no cover
        return f"TaggedPath(path={self.path!r}, tags={self.tags!r})"

    def has_tag(self, tag: str) -> bool:
        """Return True if *tag* is present (case-insensitive)."""
        return tag.lower() in (t.lower() for t in self.tags)


@dataclass
class TagReport:
    """Aggregated result of a tag-filter operation."""

    matched: List[TaggedPath] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)

    @property
    def matched_count(self) -> int:
        return len(self.matched)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    def summary(self) -> str:
        return (
            f"TagReport: {self.matched_count} matched, "
            f"{self.skipped_count} skipped"
        )


def tag_paths(
    client: VaultClient,
    paths: List[str],
    tag_map: Dict[str, List[str]],
    filter_tag: Optional[str] = None,
) -> TagReport:
    """Attach tags to *paths* using *tag_map* and optionally filter by tag.

    *tag_map* maps a path prefix (or exact path) to a list of tags.
    Paths that match no entry in *tag_map* receive an empty tag list.
    If *filter_tag* is given, only paths that carry that tag are included
    in ``TagReport.matched``; the rest go to ``TagReport.skipped``.
    """
    report = TagReport()

    for path in paths:
        # Collect tags from all prefixes that match this path.
        collected: List[str] = []
        for prefix, tags in tag_map.items():
            if path == prefix or path.startswith(prefix.rstrip("/") + "/"):
                collected.extend(tags)

        tagged = TaggedPath(path=path, tags=list(dict.fromkeys(collected)))

        if filter_tag is None or tagged.has_tag(filter_tag):
            report.matched.append(tagged)
        else:
            report.skipped.append(path)

    return report
