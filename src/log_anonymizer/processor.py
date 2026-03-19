from __future__ import annotations

import logging
import json
import shutil
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from log_anonymizer.anonymizer import AnonymizeFileStats, anonymize_file
from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns, load_patterns
from log_anonymizer.input_handler import handle_input
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.rules_loader import Rule, load_rules

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcessorConfig:
    max_workers: int = 8
    exclude_case_insensitive: bool = False
    include_builtin_rules: bool = True
    profile_sensitive_data: bool = False
    profiling_detectors: tuple[str, ...] = ("email", "ipv4", "token", "card")
    profiling_report_path: Path | None = None
    suggest_rules_output_path: Path | None = None


@dataclass(frozen=True)
class ProcessorResult:
    output_zip: Path
    total_files: int
    processed_files: int
    failed_files: int
    excluded_files: int
    profiling_report_path: Path | None = None
    suggested_rules_path: Path | None = None


def process(
    *,
    input_path: Path,
    rules_path: Path | None,
    output_dir: Path,
    output_zip_path: Path | None = None,
    exclude_path: Path | None = None,
    config: ProcessorConfig | None = None,
) -> Path:
    return process_with_result(
        input_path=input_path,
        rules_path=rules_path,
        output_dir=output_dir,
        output_zip_path=output_zip_path,
        exclude_path=exclude_path,
        config=config,
    ).output_zip


def process_with_result(
    *,
    input_path: Path,
    rules_path: Path | None,
    output_dir: Path,
    output_zip_path: Path | None = None,
    exclude_path: Path | None = None,
    config: ProcessorConfig | None = None,
) -> ProcessorResult:
    """
    Main processing pipeline.

    Responsibilities:
    1) Load input (file/dir/archive)
    2) Load exclude patterns
    3) Load rules
    4) Filter files
    5) Process each file with anonymizer (parallel)
    6) Write results to a temporary directory
    7) Compress the temporary directory into a tar.gz archive in `output_dir`

    Robustness:
    - Continues on per-file errors (logs and skips failing files)
    - Always cleans up temporary directories created during processing

    Returns:
        ProcessorResult including generated archive file path.
    """
    cfg = config or ProcessorConfig()
    output_root = output_dir.expanduser().resolve()
    if output_root.exists() and not output_root.is_dir():
        raise ValueError(f"--output must be a directory: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)

    out_zip = _resolve_output_archive_path(output_root, input_path, output_zip_path)
    out_zip.parent.mkdir(parents=True, exist_ok=True)

    user_rules = load_rules(rules_path) if rules_path is not None else []
    rules = (
        merge_rules(builtin=default_rules(), user=user_rules)
        if cfg.include_builtin_rules
        else user_rules
    )
    if not rules:
        raise ValueError("No valid rules loaded; refusing to process.")

    tmp_out_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-out-")).resolve()
    try:
        with handle_input(input_path) as prepared:
            working_dir = prepared.working_dir
            all_files = prepared.files
            logger.info(
                "pipeline_input_ready",
                extra={"working_dir": str(working_dir), "files": len(all_files)},
            )

            exclude_filter = _load_exclude_filter(
                exclude_path, base_dir=working_dir, case_insensitive=cfg.exclude_case_insensitive
            )
            files = _filter_files(all_files, exclude_filter)

            excluded_count = len(all_files) - len(files)
            logger.info(
                "pipeline_files_filtered",
                extra={"to_process": len(files), "excluded": excluded_count, "total": len(all_files)},
            )

            profiling_report_path: Path | None = None
            suggested_rules_path: Path | None = None
            if cfg.profile_sensitive_data:
                profiler = SensitiveDataProfiler(
                    config=ProfilingConfig(detectors=cfg.profiling_detectors)
                )
                report = profiler.profile_files(files, base_dir=working_dir)
                profiling_report_path = (
                    cfg.profiling_report_path
                    or (output_root / "profiling_report.json").resolve()
                )
                profiling_report_path.write_text(report.to_json(), encoding="utf-8")
                logger.info(
                    "profiling_report_written",
                    extra={"path": str(profiling_report_path)},
                )
                suggested_rules_path = (
                    cfg.suggest_rules_output_path
                    or (output_root / "suggested_rules.json").resolve()
                )
                suggested_rules_path.write_text(
                    json.dumps(report.suggested_rules, ensure_ascii=False, indent=2) + "\n",
                    encoding="utf-8",
                )
                logger.info(
                    "suggested_rules_written",
                    extra={"path": str(suggested_rules_path)},
                )

            processed, failed = _process_files_parallel(
                files=files,
                working_dir=working_dir,
                output_dir=tmp_out_dir,
                rules=rules,
                max_workers=cfg.max_workers,
            )
            _tar_gz_dir(tmp_out_dir, out_zip)
    finally:
        shutil.rmtree(tmp_out_dir, ignore_errors=True)

    logger.info(
        "pipeline_done",
        extra={
            "output_dir": str(output_root),
            "output_zip": str(out_zip),
            "processed": processed,
            "failed": failed,
            "excluded": excluded_count,
            "total": len(all_files),
        },
    )
    return ProcessorResult(
        output_zip=out_zip,
        total_files=len(all_files),
        processed_files=processed,
        failed_files=failed,
        excluded_files=excluded_count,
        profiling_report_path=profiling_report_path,
        suggested_rules_path=suggested_rules_path,
    )


def _load_exclude_filter(
    exclude_path: Path | None, *, base_dir: Path, case_insensitive: bool
) -> ExcludeFilter | None:
    patterns: list[str] = list(default_patterns())
    if exclude_path is not None:
        p = exclude_path.expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(p)
        logger.info("exclude_loaded", extra={"path": str(p)})
        patterns.extend(load_patterns(p))
    if not patterns:
        return None
    return ExcludeFilter.from_patterns(
        patterns, base_dir=base_dir, case_insensitive=case_insensitive
    )


def _filter_files(files: Iterable[Path], exclude_filter: ExcludeFilter | None) -> list[Path]:
    if exclude_filter is None:
        return list(files)
    out: list[Path] = []
    for f in files:
        if exclude_filter.should_exclude(f):
            # Debug log emitted by ExcludeFilter itself.
            continue
        out.append(f)
    return out


def _process_files_parallel(
    *,
    files: list[Path],
    working_dir: Path,
    output_dir: Path,
    rules: list[Rule],
    max_workers: int,
) -> tuple[int, int]:
    if not files:
        return 0, 0

    processed = 0
    failed = 0

    def _worker(src: Path) -> AnonymizeFileStats | None:
        try:
            rel = _safe_relative(src, working_dir)
            dest = output_dir / rel
            return anonymize_file(src, dest, rules)
        except Exception as exc:  # noqa: BLE001 (worker boundary)
            logger.exception("file_error", extra={"src": str(src), "error": str(exc)})
            return None

    logger.info("processing_start", extra={"files": len(files), "workers": max_workers})
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_worker, f): f for f in files}
        for i, fut in enumerate(as_completed(futures), start=1):
            res = fut.result()
            if res is None:
                failed += 1
            else:
                processed += 1

            if i == 1 or i % 100 == 0 or i == len(files):
                logger.info(
                    "processing_progress",
                    extra={"done": i, "total": len(files), "processed": processed, "failed": failed},
                )

    return processed, failed


def _safe_relative(path: Path, root: Path) -> Path:
    """
    Compute a stable relative path to preserve structure.
    Falls back to filename if `path` is not under `root`.
    """
    try:
        return path.resolve().relative_to(root.resolve())
    except ValueError:
        return Path(path.name)


def _is_tar_gz_path(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tar.gz") or name.endswith(".tgz")


def _resolve_output_archive_path(output_dir: Path, input_path: Path, output_zip_path: Path | None) -> Path:
    """
    Resolve the output archive path (tar.gz) such that the CLI output is a single archive
    inside `output_dir`.
    """
    output_dir = output_dir.resolve()
    if output_zip_path is None:
        base = _archive_base_name(input_path)
        return (output_dir / f"{base}.tar.gz").resolve()

    out = output_zip_path.expanduser().resolve()
    if not _is_tar_gz_path(out):
        raise ValueError(f"Output archive must end with .tar.gz or .tgz: {out}")
    if output_dir != out.parent and output_dir not in out.parents:
        raise ValueError(f"Output archive must be inside --output directory: {out}")
    return out


def _archive_base_name(input_path: Path) -> str:
    p = input_path.expanduser()
    name = p.name
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        return name[: -len(".tar.gz")]
    if lower.endswith(".tgz"):
        return name[: -len(".tgz")]
    if lower.endswith(".zip"):
        return p.stem
    # For directories or plain files, stem is a reasonable base.
    return p.stem or name


def _tar_gz_dir(root_dir: Path, out_tar_gz: Path) -> None:
    if out_tar_gz.exists():
        out_tar_gz.unlink()
    with tarfile.open(out_tar_gz, mode="w:gz") as tf:
        for p in root_dir.rglob("*"):
            if not p.is_file():
                continue
            # Avoid including the archive itself if user points it inside output_dir.
            if p.resolve() == out_tar_gz.resolve():
                continue
            tf.add(p, arcname=p.relative_to(root_dir).as_posix(), recursive=False)
