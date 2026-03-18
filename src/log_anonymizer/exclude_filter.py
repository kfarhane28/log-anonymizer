from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, Pattern

logger = logging.getLogger(__name__)

DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = (
    # Common credential/key material often present in Hadoop/Cloudera bundles.
    "creds.localjceks",
    "creds.localjceks.sha",
    "*.jceks",
    "*.jceks.sha",
    "*.keytab",
    "krb5.conf",
    "jaas.conf",
    "*.jks",
    "*keystore*",
    "*truststore*",
    "*.p12",
    "*.pfx",
    "*.pem",
    "*.key",
    "*.crt",
    "*.cer",
    "*.der",
    "*.kdb",
)


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
    _negate: tuple[bool, ...] = ()

    @classmethod
    def from_file(
        cls, exclude_file: Path, *, base_dir: Path | None = None, case_insensitive: bool = False
    ) -> "ExcludeFilter":
        patterns = tuple(load_patterns(exclude_file))
        compiled, negate = _compile_globs(patterns, case_insensitive=case_insensitive)
        return cls(
            patterns=patterns,
            base_dir=base_dir.resolve() if base_dir is not None else None,
            case_insensitive=case_insensitive,
            _compiled=compiled,
            _negate=negate,
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
        compiled, negate = _compile_globs(pat_tuple, case_insensitive=case_insensitive)
        return cls(
            patterns=pat_tuple,
            base_dir=base_dir.resolve() if base_dir is not None else None,
            case_insensitive=case_insensitive,
            _compiled=compiled,
            _negate=negate,
        )

    def should_exclude(self, file_path: Path) -> bool:
        """
        Return True if `file_path` is excluded by patterns.

        Behavior is gitignore-like:
        - patterns are evaluated in order
        - last match wins
        - patterns starting with '!' re-include (negate)
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

        excluded = False
        for idx, rx in enumerate(self._compiled):
            pattern = self.patterns[idx] if idx < len(self.patterns) else "<unknown>"
            negate = self._negate[idx] if idx < len(self._negate) else False
            for value in candidates:
                if rx.fullmatch(value):
                    excluded = not negate
                    logger.debug(
                        "file_excluded_match",
                        extra={
                            "path": abs_posix,
                            "pattern": pattern,
                            "matched": value,
                            "excluded": excluded,
                        },
                    )
                    break
        return excluded


def default_patterns() -> tuple[str, ...]:
    return DEFAULT_EXCLUDE_PATTERNS


def _compile_globs(
    patterns: Iterable[str], *, case_insensitive: bool
) -> tuple[tuple[Pattern[str], ...], tuple[bool, ...]]:
    flags = re.IGNORECASE if case_insensitive else 0
    compiled: list[Pattern[str]] = []
    negate: list[bool] = []
    for pat in patterns:
        is_negate = pat.startswith("!")
        candidate = pat[1:] if is_negate else pat
        if not candidate:
            continue
        # Translate glob -> regex and compile once for speed on large file lists.
        rx = fnmatch.translate(candidate)
        compiled.append(re.compile(rx, flags=flags))
        negate.append(is_negate)
    return tuple(compiled), tuple(negate)
