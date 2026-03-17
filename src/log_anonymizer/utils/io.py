from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO


@contextmanager
def open_text_best_effort(path: Path) -> Iterator[TextIO]:
    """
    Open a file as text with best-effort decoding:
    - try UTF-8
    - fallback to Latin-1

    Uses universal newlines on read; write side forces LF in output zip.
    """
    if not is_probably_text_file(path):
        raise ValueError(f"Binary/non-text file: {path}")

    # Prefer preserving line endings: newline="" disables newline conversion.
    try:
        f = path.open("r", encoding="utf-8", errors="strict", newline="")
        try:
            _ = f.read(4096)
            f.seek(0)
            yield f
        finally:
            f.close()
        return
    except UnicodeDecodeError:
        pass

    f = path.open("r", encoding="latin-1", errors="replace", newline="")
    try:
        yield f
    finally:
        f.close()


def is_probably_text_file(path: Path, *, sniff_bytes: int = 8192) -> bool:
    """
    Heuristic: treat files containing NUL bytes as binary.
    """
    try:
        with path.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return False
    return b"\x00" not in chunk
