from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns, load_patterns
from log_anonymizer.input_handler import handle_input
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProfilingRunResult:
    profiling_report_path: Path
    suggested_rules_path: Path
    total_files: int
    excluded_files: int
    profiled_files: int


def run_sensitive_data_profiling(
    *,
    input_path: Path,
    output_dir: Path,
    exclude_path: Path | None = None,
    exclude_case_insensitive: bool = False,
    detectors: tuple[str, ...] = ("email", "ipv4", "token", "card"),
    profiling_report_path: Path | None = None,
    suggest_rules_output_path: Path | None = None,
) -> ProfilingRunResult:
    """
    Profiling-only pipeline:
    - list input files (dir/file/archive)
    - apply excludes (built-in + optional user file)
    - scan remaining text files for potential sensitive patterns
    - write report + suggested rules JSON files
    """
    input_path = input_path.expanduser().resolve()
    output_dir = output_dir.expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    report_path = (
        profiling_report_path.expanduser().resolve()
        if profiling_report_path is not None
        else (output_dir / "profiling_report.json").resolve()
    )
    suggested_path = (
        suggest_rules_output_path.expanduser().resolve()
        if suggest_rules_output_path is not None
        else (output_dir / "suggested_rules.json").resolve()
    )

    with handle_input(input_path) as prepared:
        working_dir = prepared.working_dir
        all_files = prepared.files

        patterns = list(default_patterns())
        if exclude_path is not None:
            patterns.extend(load_patterns(exclude_path.expanduser().resolve()))
        exclude_filter = (
            ExcludeFilter.from_patterns(
                patterns, base_dir=working_dir, case_insensitive=exclude_case_insensitive
            )
            if patterns
            else None
        )
        files = [f for f in all_files if not (exclude_filter and exclude_filter.should_exclude(f))]

        profiler = SensitiveDataProfiler(config=ProfilingConfig(detectors=detectors))
        report = profiler.profile_files(files, base_dir=working_dir)

    report_path.write_text(report.to_json(), encoding="utf-8")
    suggested_path.write_text(
        json.dumps(report.suggested_rules, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    logger.info(
        "profiling_only_done",
        extra={
            "report": str(report_path),
            "suggested_rules": str(suggested_path),
            "total_files": len(all_files),
            "excluded": len(all_files) - len(files),
            "profiled": len(files),
        },
    )
    return ProfilingRunResult(
        profiling_report_path=report_path,
        suggested_rules_path=suggested_path,
        total_files=len(all_files),
        excluded_files=len(all_files) - len(files),
        profiled_files=len(files),
    )

