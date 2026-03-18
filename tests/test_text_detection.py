from __future__ import annotations

from pathlib import Path

from log_anonymizer.utils.io import is_text_file


def test_is_text_file_accepts_plain_text(tmp_path: Path) -> None:
    p = tmp_path / "a.log"
    p.write_text("hello\n", encoding="utf-8")
    assert is_text_file(p) is True


def test_is_text_file_rejects_pdf(tmp_path: Path) -> None:
    p = tmp_path / "doc"
    p.write_bytes(b"%PDF-1.7\n%binary\n\xff\x00\x10\n")
    assert is_text_file(p) is False

