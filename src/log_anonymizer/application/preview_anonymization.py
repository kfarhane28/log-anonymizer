from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.anonymizer import AnonymizeTextStats, anonymize_text_block
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
    if not rules:
        raise ValueError("No rules available for preview (provide --rules or enable built-in rules).")

    logger.info(
        "preview_start",
        extra={"lines_in": lines_in, "rules": len(rules), "builtin": bool(req.include_builtin_rules)},
    )
    anonymized_text, stats = anonymize_text_block(text, rules)
    lines_out = _count_lines(anonymized_text)
    logger.info(
        "preview_done",
        extra={
            "lines_in": lines_in,
            "lines_out": lines_out,
            "rules": len(rules),
            "replacements": stats.total_replacements,
            "triggered_rules": len(stats.triggered_rules),
        },
    )

    return PreviewAnonymizationResult(
        anonymized_text=anonymized_text,
        lines_in=lines_in,
        lines_out=lines_out,
        rules_count=len(rules),
        stats=stats,
    )


def _count_lines(text: str) -> int:
    if not text:
        return 0
    # Treat trailing newline as still representing a line (consistent with splitlines()).
    return len(text.splitlines())

