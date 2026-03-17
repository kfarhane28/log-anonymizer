from __future__ import annotations

import hashlib


def stable_hash(value: str, *, salt: str, length: int = 16) -> str:
    """
    Stable SHA-256 digest truncated to `length` hex chars.
    """
    h = hashlib.sha256()
    h.update(salt.encode("utf-8"))
    h.update(b":")
    h.update(value.encode("utf-8", errors="replace"))
    return h.hexdigest()[:length]

