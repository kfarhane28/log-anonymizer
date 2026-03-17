from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Pattern

logger = logging.getLogger(__name__)


def load_patterns(exclude_file: Path) -> list[str]:
    """
    Load glob-style exclude patterns from a `.exclude` file.

    - Blank lines are ignored
    - Lines starting with `#` are ignored
    """
    lines = exclude_file.read_text(encoding="utf-8").splitlines()
    patterns: list[str] = []
    for line in lines:
        raw = line.strip()
        if not raw or raw.startswith("#"):
            continue
        patterns.append(raw)
    return patterns


@dataclass(frozen=True)
class ExcludeFilter:
    """
    Fast matcher for glob-style exclude patterns.

    Matching strategy:
    - Match patterns against:
        - absolute POSIX path
        - relative POSIX path (relative to `base_dir`, if provided and possible)
        - basename
    - Optionally case-insensitive matching
    """

    patterns: tuple[str, ...]
    base_dir: Path | None = None
    case_insensitive: bool = False
    _compiled: tuple[Pattern[str], ...] = ()

    @classmethod
    def from_file(
        cls, exclude_file: Path, *, base_dir: Path | None = None, case_insensitive: bool = False
    ) -> "ExcludeFilter":
        patterns = tuple(load_patterns(exclude_file))
        compiled = tuple(_compile_globs(patterns, case_insensitive=case_insensitive))
        return cls(
            patterns=patterns,
            base_dir=base_dir.resolve() if base_dir is not None else None,
            case_insensitive=case_insensitive,
            _compiled=compiled,
        )

    @classmethod
    def from_patterns(
        cls,
        patterns: Iterable[str],
        *,
        base_dir: Path | None = None,
        case_insensitive: bool = False,
    ) -> "ExcludeFilter":
        pat_tuple = tuple(p.strip() for p in patterns if p and p.strip())
        compiled = tuple(_compile_globs(pat_tuple, case_insensitive=case_insensitive))
        return cls(
            patterns=pat_tuple,
            base_dir=base_dir.resolve() if base_dir is not None else None,
            case_insensitive=case_insensitive,
            _compiled=compiled,
        )

    def should_exclude(self, file_path: Path) -> bool:
        """
        Return True if `file_path` matches any exclude pattern.
        """
        abs_posix = file_path.resolve().as_posix()
        basename = file_path.name

        candidates: list[str] = [abs_posix, basename]

        if self.base_dir is not None:
            try:
                rel = file_path.resolve().relative_to(self.base_dir).as_posix()
                candidates.append(rel)
            except ValueError:
                # Not under base dir; ignore relative matching.
                pass

        # Also consider a normalized POSIX-ish representation of the provided path.
        candidates.append(str(PurePosixPath(file_path.as_posix())))

        for idx, rx in enumerate(self._compiled):
            pattern = self.patterns[idx] if idx < len(self.patterns) else "<unknown>"
            for value in candidates:
                if rx.fullmatch(value):
                    logger.debug(
                        "file_excluded",
                        extra={"path": abs_posix, "pattern": pattern, "matched": value},
                    )
                    return True
        return False


def _compile_globs(patterns: Iterable[str], *, case_insensitive: bool) -> Iterable[Pattern[str]]:
    flags = re.IGNORECASE if case_insensitive else 0
    for pat in patterns:
        # Translate glob -> regex and compile once for speed on large file lists.
        rx = fnmatch.translate(pat)
        yield re.compile(rx, flags=flags)
