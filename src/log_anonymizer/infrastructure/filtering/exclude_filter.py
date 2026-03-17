from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


@dataclass(frozen=True)
class ExcludeFilter:
    patterns: tuple[str, ...]

    @classmethod
    def from_file(cls, path: Path) -> "ExcludeFilter":
        lines = path.read_text(encoding="utf-8").splitlines()
        patterns: list[str] = []
        for line in lines:
            raw = line.strip()
            if not raw or raw.startswith("#"):
                continue
            patterns.append(raw)
        return cls(patterns=tuple(patterns))

    def is_excluded(self, rel_path: str) -> bool:
        """
        Basic gitignore-like behavior:
        - patterns are glob matched against the POSIX-style rel path and basename
        - last match wins
        - patterns starting with '!' re-include (negate)
        """
        posix = str(PurePosixPath(rel_path))
        basename = PurePosixPath(posix).name

        excluded = False
        for pat in self.patterns:
            negate = pat.startswith("!")
            candidate = pat[1:] if negate else pat
            if not candidate:
                continue

            if _match(candidate, posix) or _match(candidate, basename):
                excluded = not negate
        return excluded


def _match(pattern: str, value: str) -> bool:
    # Support patterns written like "**/foo/**" by letting fnmatch handle '*'.
    return fnmatch.fnmatch(value, pattern)

