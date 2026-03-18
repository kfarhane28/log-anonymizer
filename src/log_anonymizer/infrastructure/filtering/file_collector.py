from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.infrastructure.filtering.exclude_filter import ExcludeFilter
from log_anonymizer.utils.io import is_text_file
from log_anonymizer.utils.paths import as_posix_relpath

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CollectedFile:
    absolute_path: Path
    relative_path: str


def collect_files(
    *, root_dir: Path, only_relative: str | None, exclude: ExcludeFilter | None
) -> list[CollectedFile]:
    if only_relative is not None:
        abs_path = (root_dir / only_relative).resolve()
        if not abs_path.is_file():
            raise ValueError(f"Input file not found: {abs_path}")
        if exclude and exclude.is_excluded(only_relative):
            return []
        if not is_text_file(abs_path):
            logger.info("Skipping non-text file: %s", abs_path)
            return []
        return [CollectedFile(absolute_path=abs_path, relative_path=only_relative)]

    files: list[CollectedFile] = []
    for path in root_dir.rglob("*"):
        if not path.is_file():
            continue
        if not is_text_file(path):
            logger.info("Skipping non-text file: %s", path)
            continue
        rel = as_posix_relpath(path, root_dir)
        if exclude and exclude.is_excluded(rel):
            continue
        files.append(CollectedFile(absolute_path=path, relative_path=rel))
    return sorted(files, key=lambda f: f.relative_path)
