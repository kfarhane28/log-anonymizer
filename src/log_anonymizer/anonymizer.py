from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, TextIO

from log_anonymizer.rules_loader import Rule

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnonymizeFileStats:
    input_path: Path
    output_path: Path
    total_replacements: int
    triggered_rules: tuple[str, ...]
    replacements_by_rule: dict[str, int]


def anonymize_file(input_path: Path, output_path: Path, rules: Iterable[Rule]) -> AnonymizeFileStats:
    """
    Anonymize a log file line-by-line using the provided rules.

    Rules are applied as:
    - Check if rule.trigger is present in the line (fast substring check).
    - If triggered, apply regex replacement (`re.sub`) for that rule.

    Constraints:
    - Streaming (does not load full file in memory)
    - UTF-8 safe with fallback to Latin-1
    - Creates parent directories for output_path
    """
    in_path = input_path.resolve()
    out_path = output_path.resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    rules_list = list(rules)
    triggered: set[str] = set()
    replacements_by_rule: dict[str, int] = {}
    total_replacements = 0

    logger.info("file_start", extra={"input": str(in_path), "output": str(out_path)})
    try:
        with _open_text_best_effort(in_path) as fin, out_path.open(
            "w", encoding="utf-8", errors="replace", newline=""
        ) as fout:
            for line in fin:
                new_line = line
                for rule in rules_list:
                    if not rule.triggered_by(new_line):
                        continue
                    triggered.add(rule.description or rule.trigger)
                    new_line, n = rule.regex.subn(rule.replacement, new_line)
                    if n:
                        key = rule.description or rule.trigger
                        replacements_by_rule[key] = replacements_by_rule.get(key, 0) + n
                        total_replacements += n
                fout.write(new_line)
    except OSError as exc:
        logger.exception(
            "file_failed",
            extra={"input": str(in_path), "output": str(out_path), "error": str(exc)},
        )
        raise

    stats = AnonymizeFileStats(
        input_path=in_path,
        output_path=out_path,
        total_replacements=total_replacements,
        triggered_rules=tuple(sorted(triggered)),
        replacements_by_rule=dict(sorted(replacements_by_rule.items(), key=lambda kv: kv[0])),
    )
    logger.info(
        "file_done",
        extra={
            "input": str(in_path),
            "output": str(out_path),
            "replacements": stats.total_replacements,
            "triggered_rules": len(stats.triggered_rules),
        },
    )
    logger.debug("file_rule_stats", extra={"input": str(in_path), "by_rule": stats.replacements_by_rule})
    return stats


def _open_text_best_effort(path: Path) -> TextIO:
    """
    Open file for reading with decoding fallback.

    Returns an open file handle; caller must close it.
    """
    if _looks_binary(path):
        raise ValueError(f"Binary/non-text file: {path}")
    try:
        f = path.open("r", encoding="utf-8", errors="strict", newline="")
        # Validate decoder early.
        _ = f.read(4096)
        f.seek(0)
        return f
    except UnicodeDecodeError:
        return path.open("r", encoding="latin-1", errors="replace", newline="")


def _looks_binary(path: Path, *, sniff_bytes: int = 8192) -> bool:
    try:
        with path.open("rb") as f:
            chunk = f.read(sniff_bytes)
    except OSError:
        return True
    return b"\x00" in chunk
