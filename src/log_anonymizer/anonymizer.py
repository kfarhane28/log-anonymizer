from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator, TextIO

from log_anonymizer.rules_loader import Rule
from log_anonymizer.utils.io import is_text_file

logger = logging.getLogger(__name__)

try:
    from log_anonymizer.progress import ProgressKind, ProgressReporter, ProgressStage, now_event
except Exception:  # pragma: no cover
    ProgressReporter = object  # type: ignore[assignment]
    ProgressKind = None  # type: ignore[assignment]
    ProgressStage = None  # type: ignore[assignment]

    def now_event(**kwargs):  # type: ignore[no-redef]
        raise RuntimeError("progress module unavailable")


@dataclass(frozen=True)
class AnonymizeFileStats:
    input_path: Path
    output_path: Path
    total_replacements: int
    triggered_rules: tuple[str, ...]
    replacements_by_rule: dict[str, int]


@dataclass
class AnonymizeTextStats:
    total_replacements: int
    triggered_rules: tuple[str, ...]
    replacements_by_rule: dict[str, int]


@dataclass
class _AnonymizationAccumulator:
    triggered: set[str]
    replacements_by_rule: dict[str, int]
    total_replacements: int


def anonymize_text_block(text: str, rules: Iterable[Rule]) -> tuple[str, AnonymizeTextStats]:
    """
    Anonymize a block of text line-by-line using the provided rules.

    This is the same anonymization logic as `anonymize_file`, but in-memory.
    Newlines are preserved.
    """
    # Preserve newline chars so the output shape matches the input.
    lines = text.splitlines(keepends=True)
    out_lines, stats = _anonymize_lines(lines, rules)
    return "".join(out_lines), stats


def _anonymize_lines(lines: Iterable[str], rules: Iterable[Rule]) -> tuple[list[str], AnonymizeTextStats]:
    rules_list = list(rules)
    acc = _AnonymizationAccumulator(triggered=set(), replacements_by_rule={}, total_replacements=0)
    out_lines = list(_iter_anonymized_lines(lines, rules_list, acc))
    stats = AnonymizeTextStats(
        total_replacements=acc.total_replacements,
        triggered_rules=tuple(sorted(acc.triggered)),
        replacements_by_rule=dict(sorted(acc.replacements_by_rule.items(), key=lambda kv: kv[0])),
    )
    return out_lines, stats


def _iter_anonymized_lines(
    lines: Iterable[str], rules_list: list[Rule], acc: _AnonymizationAccumulator
) -> Iterator[str]:
    for line in lines:
        new_line = line
        for rule in rules_list:
            if not rule.triggered_by(new_line):
                continue
            key = rule.description or rule.trigger or rule.regex.pattern
            acc.triggered.add(key)
            new_line, n = rule.regex.subn(rule.replacement, new_line)
            if n:
                acc.replacements_by_rule[key] = acc.replacements_by_rule.get(key, 0) + n
                acc.total_replacements += n
        yield new_line


def anonymize_file(
    input_path: Path,
    output_path: Path,
    rules: Iterable[Rule],
    *,
    progress: ProgressReporter | None = None,
    rel_path: str | None = None,
    progress_min_bytes: int = 5 * 1024 * 1024,
    progress_min_interval_s: float = 0.2,
) -> AnonymizeFileStats:
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
    acc = _AnonymizationAccumulator(triggered=set(), replacements_by_rule={}, total_replacements=0)

    size_bytes: int | None = None
    if progress is not None:
        try:
            size_bytes = int(in_path.stat().st_size)
        except OSError:
            size_bytes = None
        progress.emit(
            now_event(
                kind=ProgressKind.FILE_START,
                stage=ProgressStage.PROCESSING,
                path=rel_path or in_path.name,
                bytes_done=0,
                bytes_total=size_bytes,
                message="anonymize_start",
            )
        )

    logger.info(
        "file_start",
        extra={"file_name": in_path.name, "input": str(in_path), "output": str(out_path)},
    )
    try:
        with _open_text_best_effort(in_path) as fin, out_path.open(
            "w", encoding="utf-8", errors="replace", newline=""
        ) as fout:
            last_emit = 0.0
            for new_line in _iter_anonymized_lines(fin, rules_list, acc):
                fout.write(new_line)
                if (
                    progress is not None
                    and size_bytes is not None
                    and size_bytes >= progress_min_bytes
                ):
                    now = time.monotonic()
                    if (now - last_emit) >= progress_min_interval_s:
                        last_emit = now
                        bytes_done: int | None = None
                        try:
                            buf = getattr(fin, "buffer", None)
                            if buf is not None and hasattr(buf, "tell"):
                                bytes_done = int(buf.tell())
                        except Exception:
                            bytes_done = None
                        if bytes_done is not None:
                            progress.emit(
                                now_event(
                                    kind=ProgressKind.FILE_PROGRESS,
                                    stage=ProgressStage.PROCESSING,
                                    path=rel_path or in_path.name,
                                    bytes_done=bytes_done,
                                    bytes_total=size_bytes,
                                )
                            )
    except OSError as exc:
        logger.exception(
            "file_failed",
            extra={"input": str(in_path), "output": str(out_path), "error": str(exc)},
        )
        if progress is not None:
            progress.emit(
                now_event(
                    kind=ProgressKind.FILE_END,
                    stage=ProgressStage.PROCESSING,
                    path=rel_path or in_path.name,
                    bytes_done=size_bytes,
                    bytes_total=size_bytes,
                    ok=False,
                    message="anonymize_failed",
                )
            )
        raise

    stats = AnonymizeFileStats(
        input_path=in_path,
        output_path=out_path,
        total_replacements=acc.total_replacements,
        triggered_rules=tuple(sorted(acc.triggered)),
        replacements_by_rule=dict(sorted(acc.replacements_by_rule.items(), key=lambda kv: kv[0])),
    )
    logger.info(
        "file_done",
        extra={
            "file_name": in_path.name,
            "input": str(in_path),
            "output": str(out_path),
            "replacements": stats.total_replacements,
            "triggered_rules": len(stats.triggered_rules),
        },
    )
    logger.debug("file_rule_stats", extra={"input": str(in_path), "by_rule": stats.replacements_by_rule})
    if progress is not None:
        progress.emit(
            now_event(
                kind=ProgressKind.FILE_END,
                stage=ProgressStage.PROCESSING,
                path=rel_path or in_path.name,
                bytes_done=size_bytes,
                bytes_total=size_bytes,
                ok=True,
                message="anonymize_done",
            )
        )
    return stats


def _open_text_best_effort(path: Path) -> TextIO:
    """
    Open file for reading with decoding fallback.

    Returns an open file handle; caller must close it.
    """
    if not is_text_file(path):
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
    # Kept for backward compatibility (and to preserve existing unit tests that import this module).
    return not is_text_file(path, sniff_bytes=sniff_bytes)
