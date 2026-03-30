from __future__ import annotations

from log_anonymizer.application.preview_highlighting import compute_changed_spans


def test_compute_changed_spans_no_change() -> None:
    assert compute_changed_spans("abc", "abc") == ()


def test_compute_changed_spans_replacement() -> None:
    spans = compute_changed_spans("user=bob", "user=[USER]")
    assert len(spans) == 1
    s = spans[0]
    assert "user=[USER]"[s.start : s.end] == "[USER]"


def test_compute_changed_spans_multiple_segments() -> None:
    out = "acct=************3456 token=[REDACTED]"
    spans = compute_changed_spans("acct=1234567890123456 token=abc.def", out)
    assert len(spans) == 2
    # Only the transformed part should be highlighted (the last 4 digits are preserved).
    assert out[spans[0].start : spans[0].end] == "************"
    assert out[spans[1].start : spans[1].end] == "[REDACTED]"


def test_compute_changed_spans_insertion() -> None:
    out = "[UUID] id"
    spans = compute_changed_spans("id", out)
    assert len(spans) == 1
    assert out[spans[0].start : spans[0].end] == "[UUID] "

