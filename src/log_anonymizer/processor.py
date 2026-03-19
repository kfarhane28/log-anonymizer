from __future__ import annotations

import logging
import json
import shutil
import tarfile
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from log_anonymizer.anonymizer import AnonymizeFileStats, anonymize_file
from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns, load_patterns
from log_anonymizer.input_handler import handle_input
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.rules_loader import Rule, load_rules
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
class ProcessorConfig:
    parallel_enabled: bool = False
    max_workers: int = 5
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
    progress: ProgressReporter | None = None,
) -> Path:
    return process_with_result(
        input_path=input_path,
        rules_path=rules_path,
        output_dir=output_dir,
        output_zip_path=output_zip_path,
        exclude_path=exclude_path,
        config=config,
        progress=progress,
    ).output_zip


def process_with_result(
    *,
    input_path: Path,
    rules_path: Path | None,
    output_dir: Path,
    output_zip_path: Path | None = None,
    exclude_path: Path | None = None,
    config: ProcessorConfig | None = None,
    progress: ProgressReporter | None = None,
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

    if progress is not None:
        progress.emit(
            now_event(kind=ProgressKind.STAGE_START, stage=ProgressStage.FINISHED, message="start")
        )

    user_rules = load_rules(rules_path) if rules_path is not None else []
    rules = (
        merge_rules(builtin=default_rules(), user=user_rules)
        if cfg.include_builtin_rules
        else user_rules
    )

    tmp_out_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-out-")).resolve()
    try:
        if progress is not None:
            progress.emit(
                now_event(kind=ProgressKind.STAGE_START, stage=ProgressStage.DISCOVERY, message="start")
            )
        with handle_input(input_path, progress=progress) as prepared:
            working_dir = prepared.working_dir
            all_files = prepared.files
            logger.info(
                "pipeline_input_ready",
                extra={"working_dir": str(working_dir), "files": len(all_files)},
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_END,
                        stage=ProgressStage.DISCOVERY,
                        current=len(all_files),
                        total=len(all_files),
                        message="done",
                    )
                )

            exclude_filter = _load_exclude_filter(
                exclude_path, base_dir=working_dir, case_insensitive=cfg.exclude_case_insensitive
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_START,
                        stage=ProgressStage.FILTERING,
                        current=0,
                        total=len(all_files),
                        message="start",
                    )
                )
            included_files, excluded_files = _filter_included_files(all_files, exclude_filter)
            excluded_count = len(excluded_files)
            _log_file_paths(
                "file_excluded_from_output",
                excluded_files,
                working_dir=working_dir,
                limit=200,
                extra={"reason": "exclude_match"},
            )
            anonymize_files: list[Path] = []
            passthrough_files: list[Path] = []
            for p in included_files:
                if is_text_file(p):
                    anonymize_files.append(p)
                else:
                    passthrough_files.append(p)
            _log_file_paths(
                "file_skipped_anonymization_non_text",
                passthrough_files,
                working_dir=working_dir,
                limit=200,
                extra={"reason": "non_text"},
            )

            if anonymize_files and not rules:
                raise ValueError("No valid rules loaded; refusing to process.")

            logger.info(
                "pipeline_files_filtered",
                extra={
                    "to_process": len(anonymize_files),
                    "passthrough": len(passthrough_files),
                    "excluded": excluded_count,
                    "total": len(all_files),
                },
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_END,
                        stage=ProgressStage.FILTERING,
                        current=len(included_files),
                        total=len(all_files),
                        message=f"included={len(included_files)} excluded={excluded_count}",
                    )
                )

            profiling_report_path: Path | None = None
            suggested_rules_path: Path | None = None
            if cfg.profile_sensitive_data:
                profiler = SensitiveDataProfiler(
                    config=ProfilingConfig(detectors=cfg.profiling_detectors)
                )
                report = profiler.profile_files(anonymize_files, base_dir=working_dir)
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

            total_in_output = len(included_files)
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_START,
                        stage=ProgressStage.PROCESSING,
                        current=0,
                        total=total_in_output,
                        message=f"anonymize={len(anonymize_files)} passthrough={len(passthrough_files)}",
                    )
                )

            done_count = 0

            def _on_file_done(ok: bool) -> None:
                nonlocal done_count
                done_count += 1
                if progress is not None:
                    progress.emit(
                        now_event(
                            kind=ProgressKind.STAGE_PROGRESS,
                            stage=ProgressStage.PROCESSING,
                            current=done_count,
                            total=total_in_output,
                            ok=ok,
                        )
                    )

            anonymized_ok, anonymized_failed = _process_files_parallel(
                files=anonymize_files,
                working_dir=working_dir,
                output_dir=tmp_out_dir,
                rules=rules,
                parallel_enabled=bool(cfg.parallel_enabled),
                max_workers=int(cfg.max_workers),
                progress=progress,
                on_file_done=_on_file_done,
            )
            passthrough_ok, passthrough_failed = _copy_passthrough_files(
                files=passthrough_files,
                working_dir=working_dir,
                output_dir=tmp_out_dir,
                parallel_enabled=bool(cfg.parallel_enabled),
                max_workers=int(cfg.max_workers),
                progress=progress,
                on_file_done=_on_file_done,
            )
            processed = anonymized_ok + passthrough_ok
            failed = anonymized_failed + passthrough_failed
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_END,
                        stage=ProgressStage.PROCESSING,
                        current=done_count,
                        total=total_in_output,
                        message=f"processed={processed} failed={failed}",
                    )
                )

            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_START,
                        stage=ProgressStage.ARCHIVE,
                        message="start",
                    )
                )
            _tar_gz_dir(tmp_out_dir, out_zip, progress=progress)
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_END,
                        stage=ProgressStage.ARCHIVE,
                        message="done",
                    )
                )
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
    if progress is not None:
        progress.emit(
            now_event(
                kind=ProgressKind.STAGE_END,
                stage=ProgressStage.FINISHED,
                message="done",
            )
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


def _is_excluded(path: Path, exclude_filter: ExcludeFilter | None) -> bool:
    if exclude_filter is None:
        return False
    return exclude_filter.should_exclude(path)


def _should_anonymize(path: Path, exclude_filter: ExcludeFilter | None) -> bool:
    return (not _is_excluded(path, exclude_filter)) and is_text_file(path)


def _should_include_in_output(path: Path, exclude_filter: ExcludeFilter | None) -> bool:
    return not _is_excluded(path, exclude_filter)


def _filter_included_files(
    files: Iterable[Path], exclude_filter: ExcludeFilter | None
) -> tuple[list[Path], list[Path]]:
    included: list[Path] = []
    excluded: list[Path] = []
    for f in files:
        if _should_include_in_output(f, exclude_filter):
            included.append(f)
        else:
            excluded.append(f)
    return included, excluded


def _copy_passthrough_files(
    *,
    files: list[Path],
    working_dir: Path,
    output_dir: Path,
    parallel_enabled: bool,
    max_workers: int,
    progress: ProgressReporter | None = None,
    on_file_done: Callable[[bool], None] | None = None,
) -> tuple[int, int]:
    if not files:
        return 0, 0

    def _worker(src: Path) -> bool:
        try:
            rel = _safe_relative(src, working_dir)
            dest = output_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if progress is not None:
                try:
                    size_bytes = int(src.stat().st_size)
                except OSError:
                    size_bytes = None
                progress.emit(
                    now_event(
                        kind=ProgressKind.FILE_START,
                        stage=ProgressStage.PROCESSING,
                        path=rel.as_posix(),
                        bytes_done=0,
                        bytes_total=size_bytes,
                        message="passthrough_start",
                    )
                )
            logger.info(
                "file_passthrough_start",
                extra={
                    "file_name": src.name,
                    "path": str(src),
                    "rel": rel.as_posix(),
                    "dest": str(dest),
                },
            )
            shutil.copy2(src, dest)
            logger.info(
                "file_passthrough_done",
                extra={
                    "file_name": src.name,
                    "path": str(src),
                    "rel": rel.as_posix(),
                    "dest": str(dest),
                },
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.FILE_END,
                        stage=ProgressStage.PROCESSING,
                        path=rel.as_posix(),
                        ok=True,
                        message="passthrough_done",
                    )
                )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                "file_passthrough_error",
                extra={"file_name": src.name, "src": str(src), "error": str(exc)},
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.FILE_END,
                        stage=ProgressStage.PROCESSING,
                        path=_safe_relative(src, working_dir).as_posix(),
                        ok=False,
                        message="passthrough_failed",
                    )
                )
            return False

    return _run_file_workers(
        files=files,
        worker=_worker,
        parallel_enabled=parallel_enabled,
        max_workers=max_workers,
        phase="passthrough",
        on_item_done=on_file_done,
    )


def _log_file_paths(
    event: str,
    files: list[Path],
    *,
    working_dir: Path,
    limit: int,
    extra: dict[str, object] | None = None,
) -> None:
    """
    Log per-file paths for pipeline decisions (exclusion, skipping anonymization, etc.).

    Uses INFO level but caps output to avoid flooding logs on huge support bundles.
    """
    if not files:
        return
    meta = dict(extra or {})
    meta.update({"count": len(files), "limit": limit})
    logger.info(f"{event}_summary", extra=meta)

    shown = 0
    for p in files:
        if shown >= limit:
            break
        rel = _safe_relative(p, working_dir)
        logger.info(
            event,
            extra={
                **(extra or {}),
                "file_name": p.name,
                "path": str(p),
                "rel": rel.as_posix(),
            },
        )
        shown += 1

    if len(files) > limit:
        logger.info(
            f"{event}_truncated",
            extra={**(extra or {}), "shown": limit, "remaining": len(files) - limit},
        )


def _process_files_parallel(
    *,
    files: list[Path],
    working_dir: Path,
    output_dir: Path,
    rules: list[Rule],
    parallel_enabled: bool,
    max_workers: int,
    progress: ProgressReporter | None = None,
    on_file_done: Callable[[bool], None] | None = None,
) -> tuple[int, int]:
    if not files:
        return 0, 0

    def _worker(src: Path) -> AnonymizeFileStats | None:
        try:
            rel = _safe_relative(src, working_dir)
            dest = output_dir / rel
            try:
                return anonymize_file(src, dest, rules, progress=progress, rel_path=rel.as_posix())
            except TypeError:
                # Backward-compat for monkeypatched / older anonymize_file callables.
                return anonymize_file(src, dest, rules)
        except Exception as exc:  # noqa: BLE001 (worker boundary)
            logger.exception("file_error", extra={"src": str(src), "error": str(exc)})
            return None

    def _bool_worker(p: Path) -> bool:
        return _worker(p) is not None

    return _run_file_workers(
        files=files,
        worker=_bool_worker,
        parallel_enabled=parallel_enabled,
        max_workers=max_workers,
        phase="anonymize",
        on_item_done=on_file_done,
    )


def _run_file_workers(
    *,
    files: list[Path],
    worker: Callable[[Path], bool],
    parallel_enabled: bool,
    max_workers: int,
    phase: str,
    on_item_done: Callable[[bool], None] | None = None,
) -> tuple[int, int]:
    processed = 0
    failed = 0

    if not parallel_enabled:
        logger.info(
            "parallel_mode_disabled",
            extra={"phase": phase, "mode": "sequential", "files": len(files)},
        )
        logger.info("processing_start", extra={"phase": phase, "files": len(files), "workers": 1})
        for i, f in enumerate(files, start=1):
            ok = worker(f)
            if ok:
                processed += 1
            else:
                failed += 1
            if on_item_done is not None:
                on_item_done(bool(ok))
            if i == 1 or i % 100 == 0 or i == len(files):
                logger.info(
                    "processing_progress",
                    extra={"phase": phase, "done": i, "total": len(files), "processed": processed, "failed": failed},
                )
        return processed, failed

    if max_workers <= 0:
        raise ValueError(f"max_workers must be >= 1 (got {max_workers})")

    logger.info(
        "parallel_mode_enabled",
        extra={"phase": phase, "mode": "parallel", "max_workers": max_workers, "files": len(files)},
    )
    logger.info("processing_start", extra={"phase": phase, "files": len(files), "workers": max_workers})

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(worker, f) for f in files]
        for i, fut in enumerate(as_completed(futures), start=1):
            ok = bool(fut.result())
            if ok:
                processed += 1
            else:
                failed += 1
            if on_item_done is not None:
                on_item_done(ok)
            if i == 1 or i % 100 == 0 or i == len(files):
                logger.info(
                    "processing_progress",
                    extra={"phase": phase, "done": i, "total": len(files), "processed": processed, "failed": failed},
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


def _tar_gz_dir(
    root_dir: Path, out_tar_gz: Path, *, progress: ProgressReporter | None = None
) -> None:
    if out_tar_gz.exists():
        out_tar_gz.unlink()
    with tarfile.open(out_tar_gz, mode="w:gz") as tf:
        files = [p for p in root_dir.rglob("*") if p.is_file()]
        files.sort(key=lambda p: p.relative_to(root_dir).as_posix())
        total = len(files)
        if progress is not None:
            progress.emit(
                now_event(
                    kind=ProgressKind.STAGE_PROGRESS,
                    stage=ProgressStage.ARCHIVE,
                    current=0,
                    total=total,
                    message="collect",
                )
            )
        for i, p in enumerate(files, start=1):
            # Avoid including the archive itself if user points it inside output_dir.
            if p.resolve() == out_tar_gz.resolve():
                continue
            tf.add(p, arcname=p.relative_to(root_dir).as_posix(), recursive=False)
            if progress is not None:
                if i == 1 or i == total or i % 200 == 0:
                    progress.emit(
                        now_event(
                            kind=ProgressKind.STAGE_PROGRESS,
                            stage=ProgressStage.ARCHIVE,
                            current=i,
                            total=total,
                            message="writing",
                        )
                    )
