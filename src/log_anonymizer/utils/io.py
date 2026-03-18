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
    if not is_text_file(path):
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


def is_text_file(path: str | Path, *, sniff_bytes: int = 8192) -> bool:
    """
    Robust text detection (extension-agnostic).

    Strategy:
    - Read a small initial chunk
    - Reject known binary signatures and NUL bytes
    - Reject chunks with a high ratio of control/non-printable bytes
    - Try UTF-8 strict decoding; if it fails, accept as text only if the chunk still
      looks like text (e.g., Latin-1 logs are common in the wild)
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return False
    try:
        with p.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return False
    return is_text_bytes(chunk)


def is_text_bytes(chunk: bytes) -> bool:
    if not chunk:
        return True
    if _has_binary_signature(chunk):
        return False
    if _looks_binary_bytes(chunk):
        return False
    try:
        chunk.decode("utf-8", errors="strict")
        return True
    except UnicodeDecodeError:
        return True


def _has_binary_signature(chunk: bytes) -> bool:
    # Common binary "magic numbers" (avoid relying on extensions).
    signatures = (
        b"%PDF-",
        b"\x89PNG\r\n\x1a\n",
        b"\xff\xd8\xff",  # JPEG
        b"GIF87a",
        b"GIF89a",
        b"PK\x03\x04",  # ZIP/JAR
        b"\x1f\x8b",  # gzip
        b"PAR1",  # parquet
        b"Obj\x01",  # Avro object container file
    )
    for sig in signatures:
        if chunk.startswith(sig):
            return True
    return False


def _looks_binary_bytes(chunk: bytes) -> bool:
    # Fast path: NUL is a strong binary indicator.
    if b"\x00" in chunk:
        return True

    # Count suspicious control bytes (excluding common whitespace).
    allowed_controls = {9, 10, 12, 13}  # \t \n \f \r
    suspicious = 0
    for b in chunk:
        # Include C1 control range (0x80-0x9F) as suspicious too; it's uncommon in plain logs
        # and often indicates binary or compressed content.
        if b == 127 or (b < 32 and b not in allowed_controls) or (128 <= b < 160):
            suspicious += 1

    # If a large part of the sample is non-text, treat as binary.
    # Threshold chosen to avoid misclassifying structured text with occasional control chars.
    return (suspicious / len(chunk)) > 0.30


def is_probably_text_file(path: Path, *, sniff_bytes: int = 8192) -> bool:
    """
    Backward-compatible alias for older code paths.
    """
    return is_text_file(path, sniff_bytes=sniff_bytes)
