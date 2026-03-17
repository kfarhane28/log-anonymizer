from __future__ import annotations

from pathlib import Path

import pytest

from log_anonymizer.anonymizer import anonymize_file
from log_anonymizer.rules_loader import Rule


def test_anonymize_empty_file(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("", encoding="utf-8")

    rule = Rule(
        description="replace secret",
        trigger="SECRET=",
        regex=__import__("re").compile(r"SECRET=[^ ]+"),
        replacement="SECRET=[REDACTED]",
        case_sensitive=True,
    )
    stats = anonymize_file(inp, out, [rule])
    assert out.read_text(encoding="utf-8") == ""
    assert stats.total_replacements == 0


def test_anonymize_applies_only_when_trigger_present(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    out = tmp_path / "out.log"
    inp.write_text("nope\nSECRET=abc other\n", encoding="utf-8")

    rule = Rule(
        description="replace secret",
        trigger="SECRET=",
        regex=__import__("re").compile(r"SECRET=[^ ]+"),
        replacement="SECRET=[REDACTED]",
        case_sensitive=True,
    )
    stats = anonymize_file(inp, out, [rule])
    assert out.read_text(encoding="utf-8") == "nope\nSECRET=[REDACTED] other\n"
    assert stats.total_replacements == 1
    assert "replace secret" in stats.triggered_rules


def test_anonymize_rejects_binary_content(tmp_path: Path) -> None:
    inp = tmp_path / "bin.log"
    out = tmp_path / "out.log"
    inp.write_bytes(b"\x00\x01\x02SECRET=abc")

    rule = Rule(
        description="replace secret",
        trigger="SECRET=",
        regex=__import__("re").compile(r"SECRET=[^ ]+"),
        replacement="SECRET=[REDACTED]",
        case_sensitive=True,
    )
    with pytest.raises(ValueError):
        anonymize_file(inp, out, [rule])

