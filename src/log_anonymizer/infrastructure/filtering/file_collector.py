from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.infrastructure.filtering.exclude_filter import ExcludeFilter
from log_anonymizer.utils.paths import as_posix_relpath


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
        return [CollectedFile(absolute_path=abs_path, relative_path=only_relative)]

    files: list[CollectedFile] = []
    for path in root_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = as_posix_relpath(path, root_dir)
        if exclude and exclude.is_excluded(rel):
            continue
        files.append(CollectedFile(absolute_path=path, relative_path=rel))
    return sorted(files, key=lambda f: f.relative_path)

