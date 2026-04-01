from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.anonymizer import AnonymizeTextStats, anonymize_text_block
from log_anonymizer.application.preview_highlighting import ChangedSpan, compute_changed_spans
from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.rules_loader import Rule, load_rules

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PreviewAnonymizationRequest:
    text: str
    rules_path: Path | None = None
    include_builtin_rules: bool = True


@dataclass(frozen=True)
class PreviewAnonymizationResult:
    anonymized_text: str
    lines_in: int
    lines_out: int
    rules_count: int
    stats: AnonymizeTextStats
    line_details: tuple["PreviewLineDetail", ...]


@dataclass(frozen=True)
class PreviewLineDetail:
    original: str
    anonymized: str
    changed_spans: tuple[ChangedSpan, ...]


def preview_anonymization(req: PreviewAnonymizationRequest) -> PreviewAnonymizationResult:
    """
    In-memory anonymization preview for the UI.

    Reuses the same rule loading/merging behavior as the CLI pipeline and the same
    line-by-line anonymization logic as file processing.
    """
    text = req.text or ""
    lines_in = _count_lines(text)

    user_rules: list[Rule] = load_rules(req.rules_path) if req.rules_path is not None else []
    rules = (
        merge_rules(builtin=default_rules(), user=user_rules) if req.include_builtin_rules else list(user_rules)
    )
    enabled_rules = [r for r in rules if getattr(r, "enabled", True)]
    if not enabled_rules:
        raise ValueError("No rules available for preview (provide --rules or enable built-in rules).")

    logger.info(
        "preview_start",
        extra={"lines_in": lines_in, "rules": len(enabled_rules), "builtin": bool(req.include_builtin_rules)},
    )
    anonymized_text, stats = anonymize_text_block(text, enabled_rules)
    lines_out = _count_lines(anonymized_text)
    logger.info(
        "preview_done",
        extra={
            "lines_in": lines_in,
            "lines_out": lines_out,
            "rules": len(enabled_rules),
            "replacements": stats.total_replacements,
            "triggered_rules": len(stats.triggered_rules),
        },
    )

    in_lines = text.splitlines()
    out_lines = anonymized_text.splitlines()
    line_details: list[PreviewLineDetail] = []
    for i in range(max(len(in_lines), len(out_lines))):
        original = in_lines[i] if i < len(in_lines) else ""
        anonymized = out_lines[i] if i < len(out_lines) else ""
        line_details.append(
            PreviewLineDetail(
                original=original,
                anonymized=anonymized,
                changed_spans=compute_changed_spans(original, anonymized),
            )
        )

    return PreviewAnonymizationResult(
        anonymized_text=anonymized_text,
        lines_in=lines_in,
        lines_out=lines_out,
        rules_count=len(enabled_rules),
        stats=stats,
        line_details=tuple(line_details),
    )


def _count_lines(text: str) -> int:
    if not text:
        return 0
    # Treat trailing newline as still representing a line (consistent with splitlines()).
    return len(text.splitlines())
