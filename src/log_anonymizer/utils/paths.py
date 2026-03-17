from __future__ import annotations

from pathlib import Path


def as_posix_relpath(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()

