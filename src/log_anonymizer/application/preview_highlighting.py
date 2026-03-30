from __future__ import annotations

import difflib
from dataclasses import dataclass


@dataclass(frozen=True)
class ChangedSpan:
    """
    Half-open span [start, end) in the anonymized line.

    Used by the Streamlit preview to highlight which output segments were
    transformed by anonymization.
    """

    start: int
    end: int


def compute_changed_spans(original_line: str, anonymized_line: str) -> tuple[ChangedSpan, ...]:
    """
    Compute output-side spans that differ from the input line.

    Notes:
    - Only highlights what exists in the anonymized output (replace/insert).
    - Deletes can't be highlighted because the content is removed.
    """
    if original_line == anonymized_line:
        return ()

    sm = difflib.SequenceMatcher(a=original_line, b=anonymized_line, autojunk=False)
    spans: list[ChangedSpan] = []
    for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
        if tag in {"replace", "insert"} and j1 != j2:
            spans.append(ChangedSpan(start=j1, end=j2))

    if not spans:
        return ()

    # Merge overlapping/adjacent spans to avoid noisy markup.
    spans.sort(key=lambda s: (s.start, s.end))
    merged: list[ChangedSpan] = [spans[0]]
    for s in spans[1:]:
        last = merged[-1]
        if s.start <= last.end:
            merged[-1] = ChangedSpan(start=last.start, end=max(last.end, s.end))
        else:
            merged.append(s)
    return tuple(merged)

