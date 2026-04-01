from __future__ import annotations

import logging
import json
import os
import shutil
import tarfile
import tempfile
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Callable, Iterable, Literal

from log_anonymizer.anonymizer import (
    AnonymizationCancelled,
    anonymize_file,
)
from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns, load_patterns
from log_anonymizer.filename_anonymizer import FilenameAnonymizer
from log_anonymizer.input_handler import handle_input
from log_anonymizer.profiling.profiler import ProfilingConfig, SensitiveDataProfiler
from log_anonymizer.rules_loader import Rule, load_rules
from log_anonymizer.rule_actions import ActionContext
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
    anonymize_filenames: bool = False
    profiling_detectors: tuple[str, ...] = ("email", "ipv4", "token", "card")
    profiling_report_path: Path | None = None
    suggest_rules_output_path: Path | None = None
    cancellation_token: "CancellationToken | None" = None
    rollback_on_cancel: bool = False
    anonymization_salt: str | None = None


@dataclass(frozen=True)
class ProcessorResult:
    output_zip: Path
    total_files: int
    processed_files: int
    failed_files: int
    excluded_files: int
    profiling_report_path: Path | None = None
    suggested_rules_path: Path | None = None
    cancelled: bool = False
    rolled_back: bool = False


class CancellationToken:
    """Thread-safe cancellation flag shared across UI and processing workers."""

    def __init__(self) -> None:
        self._event = Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


WorkerOutcome = Literal["processed", "failed", "cancelled"]


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
    action_context = ActionContext(salt=cfg.anonymization_salt or "")
    cancelled = False
    rolled_back = False
    all_files: list[Path] = []
    processed = 0
    failed = 0
    excluded_count = 0
    profiling_report_path: Path | None = None
    suggested_rules_path: Path | None = None

    output_root = output_dir.expanduser().resolve()
    if output_root.exists() and not output_root.is_dir():
        raise ValueError(f"--output must be a directory: {output_root}")
    output_root.mkdir(parents=True, exist_ok=True)

    out_zip = _resolve_output_archive_path(
        output_root,
        input_path,
        output_zip_path,
        anonymize_filenames=bool(cfg.anonymize_filenames),
    )
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
    enabled_rules = [r for r in rules if getattr(r, "enabled", True)]

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

            if anonymize_files and not enabled_rules:
                raise ValueError("No valid rules loaded; refusing to process.")

            output_relpath_for = None
            if cfg.anonymize_filenames:
                rels = [_safe_relative(p, working_dir) for p in included_files]
                fn = FilenameAnonymizer(rules=enabled_rules, action_context=action_context)
                rel_map, stats = fn.build_relpath_map(rels)
                logger.info(
                    "filename_anonymization_enabled",
                    extra={
                        "paths_total": stats.paths_total,
                        "paths_changed": stats.paths_changed,
                        "components_changed": stats.components_changed,
                        "collisions_resolved": stats.collisions_resolved,
                    },
                )
                changed = [(k, v) for k, v in rel_map.items() if k.as_posix() != v.as_posix()]
                if changed:
                    for k, v in changed[:80]:
                        logger.debug(
                            "filename_anonymized",
                            extra={"rel": k.as_posix(), "out_rel": v.as_posix()},
                        )
                    if len(changed) > 80:
                        logger.debug(
                            "filename_anonymized_truncated",
                            extra={"shown": 80, "remaining": len(changed) - 80},
                        )

                def output_relpath_for(p: Path) -> Path:  # type: ignore[misc]
                    rel = Path(_safe_relative(p, working_dir).as_posix())
                    return rel_map.get(rel, rel)

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

            if cfg.profile_sensitive_data and not _is_cancelled(cfg):
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
            elif _is_cancelled(cfg):
                cancelled = True

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

            anonymized_ok, anonymized_failed, anonymized_cancelled = _process_files_parallel(
                files=anonymize_files,
                working_dir=working_dir,
                output_dir=tmp_out_dir,
                rules=enabled_rules,
                parallel_enabled=bool(cfg.parallel_enabled),
                max_workers=int(cfg.max_workers),
                progress=progress,
                on_file_done=_on_file_done,
                cancel_requested=lambda: _is_cancelled(cfg),
                action_context=action_context,
                output_relpath_for=output_relpath_for,
            )
            cancelled = cancelled or anonymized_cancelled > 0 or _is_cancelled(cfg)

            passthrough_ok = 0
            passthrough_failed = 0
            passthrough_cancelled = 0
            if not cancelled:
                passthrough_ok, passthrough_failed, passthrough_cancelled = _copy_passthrough_files(
                    files=passthrough_files,
                    working_dir=working_dir,
                    output_dir=tmp_out_dir,
                    parallel_enabled=bool(cfg.parallel_enabled),
                    max_workers=int(cfg.max_workers),
                    progress=progress,
                    on_file_done=_on_file_done,
                    cancel_requested=lambda: _is_cancelled(cfg),
                    output_relpath_for=output_relpath_for,
                )
                cancelled = cancelled or passthrough_cancelled > 0 or _is_cancelled(cfg)

            processed = anonymized_ok + passthrough_ok
            failed = anonymized_failed + passthrough_failed
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_END,
                        stage=ProgressStage.PROCESSING,
                        current=done_count,
                        total=total_in_output,
                        message=f"processed={processed} failed={failed} cancelled={int(cancelled)}",
                    )
                )

            if cancelled and cfg.rollback_on_cancel:
                rolled_back = True
                if out_zip.exists():
                    out_zip.unlink()
            else:
                if progress is not None:
                    progress.emit(
                        now_event(
                            kind=ProgressKind.STAGE_START,
                            stage=ProgressStage.ARCHIVE,
                            message="start",
                        )
                    )
                try:
                    # If cancellation happened during processing, finalize a partial archive.
                    archive_cancel = (lambda: _is_cancelled(cfg)) if not cancelled else None
                    _tar_gz_dir(
                        tmp_out_dir,
                        out_zip,
                        progress=progress,
                        cancel_requested=archive_cancel,
                    )
                except AnonymizationCancelled:
                    cancelled = True
                    rolled_back = True
                    if out_zip.exists():
                        out_zip.unlink()
                if progress is not None:
                    progress.emit(
                        now_event(
                            kind=ProgressKind.STAGE_END,
                            stage=ProgressStage.ARCHIVE,
                            message="done" if not rolled_back else "cancelled",
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
            "cancelled": cancelled,
            "rolled_back": rolled_back,
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
        cancelled=cancelled,
        rolled_back=rolled_back,
    )


def _is_cancelled(cfg: ProcessorConfig) -> bool:
    token = cfg.cancellation_token
    return bool(token is not None and token.is_cancelled())


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
    cancel_requested: Callable[[], bool] | None = None,
    output_relpath_for: Callable[[Path], Path] | None = None,
) -> tuple[int, int, int]:
    if not files:
        return 0, 0, 0

    def _worker(src: Path) -> WorkerOutcome:
        try:
            if cancel_requested is not None and cancel_requested():
                return "cancelled"
            rel = _safe_relative(src, working_dir)
            out_rel = output_relpath_for(src) if output_relpath_for is not None else rel
            dest = output_dir / out_rel
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
                        path=out_rel.as_posix(),
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
                    "out_rel": out_rel.as_posix(),
                    "dest": str(dest),
                },
            )
            committed = _copy_file_atomic(src, dest, cancel_requested=cancel_requested)
            if not committed:
                if progress is not None:
                    progress.emit(
                        now_event(
                            kind=ProgressKind.FILE_END,
                            stage=ProgressStage.PROCESSING,
                            path=out_rel.as_posix(),
                            ok=False,
                            message="passthrough_cancelled",
                        )
                    )
                return "cancelled"
            logger.info(
                "file_passthrough_done",
                extra={
                    "file_name": src.name,
                    "path": str(src),
                    "rel": rel.as_posix(),
                    "out_rel": out_rel.as_posix(),
                    "dest": str(dest),
                },
            )
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.FILE_END,
                        stage=ProgressStage.PROCESSING,
                        path=out_rel.as_posix(),
                        ok=True,
                        message="passthrough_done",
                    )
                )
            return "processed"
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
                        path=(
                            (output_relpath_for(src) if output_relpath_for is not None else rel)
                        ).as_posix(),
                        ok=False,
                        message="passthrough_failed",
                    )
                )
            return "failed"

    return _run_file_workers(
        files=files,
        worker=_worker,
        parallel_enabled=parallel_enabled,
        max_workers=max_workers,
        phase="passthrough",
        on_item_done=on_file_done,
        cancel_requested=cancel_requested,
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
    cancel_requested: Callable[[], bool] | None = None,
    action_context: ActionContext | None = None,
    output_relpath_for: Callable[[Path], Path] | None = None,
) -> tuple[int, int, int]:
    if not files:
        return 0, 0, 0

    def _worker(src: Path) -> WorkerOutcome:
        try:
            if cancel_requested is not None and cancel_requested():
                return "cancelled"
            rel = _safe_relative(src, working_dir)
            out_rel = output_relpath_for(src) if output_relpath_for is not None else rel
            dest = output_dir / out_rel
            try:
                anonymize_file(
                    src,
                    dest,
                    rules,
                    progress=progress,
                    rel_path=out_rel.as_posix(),
                    cancel_requested=cancel_requested,
                    action_context=action_context,
                )
            except TypeError:
                # Backward-compat for monkeypatched / older anonymize_file callables.
                anonymize_file(src, dest, rules)
            return "processed"
        except AnonymizationCancelled:
            return "cancelled"
        except Exception as exc:  # noqa: BLE001 (worker boundary)
            logger.exception("file_error", extra={"src": str(src), "error": str(exc)})
            return "failed"

    return _run_file_workers(
        files=files,
        worker=_worker,
        parallel_enabled=parallel_enabled,
        max_workers=max_workers,
        phase="anonymize",
        on_item_done=on_file_done,
        cancel_requested=cancel_requested,
    )


def _run_file_workers(
    *,
    files: list[Path],
    worker: Callable[[Path], WorkerOutcome],
    parallel_enabled: bool,
    max_workers: int,
    phase: str,
    on_item_done: Callable[[bool], None] | None = None,
    cancel_requested: Callable[[], bool] | None = None,
) -> tuple[int, int, int]:
    processed = 0
    failed = 0
    cancelled = 0

    if not parallel_enabled:
        logger.info(
            "parallel_mode_disabled",
            extra={"phase": phase, "mode": "sequential", "files": len(files)},
        )
        logger.info("processing_start", extra={"phase": phase, "files": len(files), "workers": 1})
        for i, f in enumerate(files, start=1):
            if cancel_requested is not None and cancel_requested():
                cancelled += len(files) - (i - 1)
                break
            outcome = worker(f)
            if outcome == "processed":
                processed += 1
            elif outcome == "failed":
                failed += 1
            else:
                cancelled += 1
            if on_item_done is not None:
                on_item_done(outcome == "processed")
            if i == 1 or i % 100 == 0 or i == len(files):
                logger.info(
                    "processing_progress",
                    extra={
                        "phase": phase,
                        "done": i,
                        "total": len(files),
                        "processed": processed,
                        "failed": failed,
                        "cancelled": cancelled,
                    },
                )
        return processed, failed, cancelled

    if max_workers <= 0:
        raise ValueError(f"max_workers must be >= 1 (got {max_workers})")

    logger.info(
        "parallel_mode_enabled",
        extra={"phase": phase, "mode": "parallel", "max_workers": max_workers, "files": len(files)},
    )
    logger.info("processing_start", extra={"phase": phase, "files": len(files), "workers": max_workers})

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        pending = set()
        files_iter = iter(files)
        started = 0
        done = 0

        def _submit_next() -> bool:
            nonlocal started
            try:
                f = next(files_iter)
            except StopIteration:
                return False
            pending.add(pool.submit(worker, f))
            started += 1
            return True

        while len(pending) < max_workers:
            if cancel_requested is not None and cancel_requested():
                break
            if not _submit_next():
                break

        while pending:
            done_set, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in done_set:
                done += 1
                try:
                    outcome = fut.result()
                except Exception:  # pragma: no cover - safety boundary
                    logger.exception("worker_future_failed", extra={"phase": phase})
                    outcome = "failed"
                if outcome == "processed":
                    processed += 1
                elif outcome == "failed":
                    failed += 1
                else:
                    cancelled += 1
                if on_item_done is not None:
                    on_item_done(outcome == "processed")
                if done == 1 or done % 100 == 0 or done == len(files):
                    logger.info(
                        "processing_progress",
                        extra={
                            "phase": phase,
                            "done": done,
                            "total": len(files),
                            "processed": processed,
                            "failed": failed,
                            "cancelled": cancelled,
                        },
                    )

            while len(pending) < max_workers:
                if cancel_requested is not None and cancel_requested():
                    break
                if not _submit_next():
                    break

        cancelled += max(0, len(files) - started)

    return processed, failed, cancelled


def _copy_file_atomic(
    src: Path,
    dest: Path,
    *,
    cancel_requested: Callable[[], bool] | None = None,
) -> bool:
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{dest.name}.",
        suffix=".tmp",
        dir=str(dest.parent),
    )
    os.close(tmp_fd)
    tmp_dest = Path(tmp_name)
    try:
        if cancel_requested is not None and cancel_requested():
            return False
        shutil.copy2(src, tmp_dest)
        if cancel_requested is not None and cancel_requested():
            return False
        os.replace(tmp_dest, dest)
        return True
    finally:
        try:
            if tmp_dest.exists():
                tmp_dest.unlink()
        except OSError:
            pass


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


def _resolve_output_archive_path(
    output_dir: Path,
    input_path: Path,
    output_zip_path: Path | None,
    *,
    anonymize_filenames: bool,
) -> Path:
    """
    Resolve the output archive path (tar.gz) such that the CLI output is a single archive
    inside `output_dir`.
    """
    output_dir = output_dir.resolve()
    if output_zip_path is None:
        if anonymize_filenames:
            base = "anonymized_output"
            out = (output_dir / f"{base}.tar.gz").resolve()
            if not out.exists():
                return out
            i = 2
            while True:
                candidate = (output_dir / f"{base}__{i}.tar.gz").resolve()
                if not candidate.exists():
                    return candidate
                i += 1
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
    root_dir: Path,
    out_tar_gz: Path,
    *,
    progress: ProgressReporter | None = None,
    cancel_requested: Callable[[], bool] | None = None,
) -> None:
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=f".{out_tar_gz.name}.",
        suffix=".tmp",
        dir=str(out_tar_gz.parent),
    )
    os.close(tmp_fd)
    tmp_tar_path = Path(tmp_name)
    if out_tar_gz.exists():
        out_tar_gz.unlink()
    try:
        with tarfile.open(tmp_tar_path, mode="w:gz") as tf:
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
                if cancel_requested is not None and cancel_requested():
                    raise AnonymizationCancelled("cancelled while writing archive")
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
        os.replace(tmp_tar_path, out_tar_gz)
    finally:
        try:
            if tmp_tar_path.exists():
                tmp_tar_path.unlink()
        except OSError:
            pass
