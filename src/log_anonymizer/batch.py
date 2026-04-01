from __future__ import annotations

import json
import logging
import re
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal

from log_anonymizer.processor import ProcessorConfig, ProcessorResult, process_with_result
from log_anonymizer.progress import (
    ProgressKind,
    ProgressReporter,
    ProgressStage,
    now_event,
)

logger = logging.getLogger(__name__)

BatchItemStatus = Literal["success", "failed", "cancelled", "skipped"]


@dataclass(frozen=True)
class BatchItemResult:
    index: int
    input_path: Path
    status: BatchItemStatus
    output_dir: Path
    output_archive: Path | None = None
    error: str | None = None
    result: ProcessorResult | None = None


@dataclass(frozen=True)
class BatchResult:
    batch_dir: Path
    items: list[BatchItemResult]
    summary_path: Path

    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def succeeded(self) -> int:
        return sum(1 for it in self.items if it.status == "success")

    @property
    def failed(self) -> int:
        return sum(1 for it in self.items if it.status == "failed")

    @property
    def cancelled(self) -> int:
        return sum(1 for it in self.items if it.status == "cancelled")

    @property
    def skipped(self) -> int:
        return sum(1 for it in self.items if it.status == "skipped")


_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe_output_component(name: str) -> str:
    base = (name or "").strip()
    if not base:
        return "input"
    base = base.replace("\n", "").replace("\r", "")
    cleaned = _SAFE_COMPONENT_RE.sub("_", base).strip(" .")
    return cleaned or "input"


def _default_batch_dir_name() -> str:
    # Human-friendly and filesystem-safe. Example: batch-20260401-153012
    return "batch-" + datetime.now().strftime("%Y%m%d-%H%M%S")


def _derive_per_input_config(cfg: ProcessorConfig, *, output_dir: Path) -> ProcessorConfig:
    profiling_report_path = None
    if cfg.profiling_report_path is not None:
        profiling_report_path = (output_dir / cfg.profiling_report_path.name).resolve()
    suggest_rules_output_path = None
    if cfg.suggest_rules_output_path is not None:
        suggest_rules_output_path = (output_dir / cfg.suggest_rules_output_path.name).resolve()
    return ProcessorConfig(
        parallel_enabled=cfg.parallel_enabled,
        max_workers=cfg.max_workers,
        exclude_case_insensitive=cfg.exclude_case_insensitive,
        include_builtin_rules=cfg.include_builtin_rules,
        profile_sensitive_data=cfg.profile_sensitive_data,
        anonymize_filenames=cfg.anonymize_filenames,
        profiling_detectors=cfg.profiling_detectors,
        profiling_report_path=profiling_report_path,
        suggest_rules_output_path=suggest_rules_output_path,
        cancellation_token=cfg.cancellation_token,
        rollback_on_cancel=cfg.rollback_on_cancel,
        anonymization_salt=cfg.anonymization_salt,
    )


def process_batch_with_result(
    *,
    inputs: list[Path],
    rules_path: Path | None,
    output_dir: Path,
    exclude_path: Path | None = None,
    config: ProcessorConfig | None = None,
    batch_parallel_enabled: bool = False,
    batch_max_workers: int = 2,
    batch_dir_name: str | None = None,
    progress: ProgressReporter | None = None,
) -> BatchResult:
    """
    Process multiple top-level inputs in a single batch job.

    - Each input is processed independently (errors are captured per input).
    - When batch_parallel_enabled=True, multiple inputs run concurrently.
    - Outputs are isolated per input under a batch directory to avoid collisions.
    """
    if not inputs:
        raise ValueError("Batch inputs list is empty.")
    if batch_max_workers <= 0:
        raise ValueError(f"batch_max_workers must be >= 1 (got {batch_max_workers})")

    cfg = config or ProcessorConfig()
    out_root = output_dir.expanduser().resolve()
    out_root.mkdir(parents=True, exist_ok=True)

    batch_dir = (out_root / (batch_dir_name or _default_batch_dir_name())).resolve()
    batch_dir.mkdir(parents=True, exist_ok=True)

    total = len(inputs)
    done = 0

    if progress is not None:
        progress.emit(
            now_event(
                kind=ProgressKind.STAGE_START,
                stage=ProgressStage.PROCESSING,
                current=0,
                total=total,
                message="batch_start",
            )
        )

    def _run_one(idx: int, input_path: Path) -> BatchItemResult:
        safe = _safe_output_component(input_path.name)
        item_dir = (batch_dir / f"{idx:03d}-{safe}").resolve()
        item_dir.mkdir(parents=True, exist_ok=True)
        item_cfg = _derive_per_input_config(cfg, output_dir=item_dir)
        # Avoid mixing per-file events for different inputs.
        result = process_with_result(
            input_path=input_path,
            rules_path=rules_path,
            output_dir=item_dir,
            exclude_path=exclude_path,
            config=item_cfg,
            progress=None,
        )
        status: BatchItemStatus
        if result.cancelled:
            status = "cancelled"
        else:
            status = "success"
        out = result.output_zip if result.output_zip.exists() else None
        return BatchItemResult(
            index=idx,
            input_path=input_path,
            status=status,
            output_dir=item_dir,
            output_archive=out,
            result=result,
        )

    slots: list[BatchItemResult | None] = [None] * total

    # Sequential mode keeps ordering and simplifies cancellation behavior.
    if not batch_parallel_enabled or total == 1:
        for idx, p in enumerate(inputs, start=1):
            if cfg.cancellation_token is not None and cfg.cancellation_token.is_cancelled():
                slots[idx - 1] = BatchItemResult(
                    index=idx,
                    input_path=p,
                    status="skipped",
                    output_dir=batch_dir,
                    error="cancelled_before_start",
                )
                continue
            try:
                logger.info(
                    "batch_item_start",
                    extra={"input": str(p), "idx": idx, "total": total},
                )
                r = _run_one(idx, p)
                slots[idx - 1] = r
                logger.info(
                    "batch_item_done",
                    extra={
                        "input": str(p),
                        "idx": idx,
                        "total": total,
                        "status": r.status,
                        "output_archive": str(r.output_archive) if r.output_archive else None,
                    },
                )
            except Exception as exc:  # noqa: BLE001
                logger.exception(
                    "batch_item_failed",
                    extra={"input": str(p), "idx": idx, "total": total, "error": str(exc)},
                )
                slots[idx - 1] = BatchItemResult(
                    index=idx,
                    input_path=p,
                    status="failed",
                    output_dir=(batch_dir / f"{idx:03d}-{_safe_output_component(p.name)}").resolve(),
                    error=f"{type(exc).__name__}: {exc}",
                )
            done += 1
            if progress is not None:
                progress.emit(
                    now_event(
                        kind=ProgressKind.STAGE_PROGRESS,
                        stage=ProgressStage.PROCESSING,
                        current=done,
                        total=total,
                        message=f"input={p.name}",
                    )
                )
    else:
        pending: dict[Future[BatchItemResult], tuple[int, Path]] = {}
        with ThreadPoolExecutor(max_workers=int(batch_max_workers)) as ex:
            for idx, p in enumerate(inputs, start=1):
                if cfg.cancellation_token is not None and cfg.cancellation_token.is_cancelled():
                    slots[idx - 1] = BatchItemResult(
                        index=idx,
                        input_path=p,
                        status="skipped",
                        output_dir=batch_dir,
                        error="cancelled_before_start",
                    )
                    continue
                logger.info(
                    "batch_item_submit",
                    extra={"input": str(p), "idx": idx, "total": total},
                )
                fut = ex.submit(_run_one, idx, p)
                pending[fut] = (idx, p)

            while pending:
                done_futs, _rest = wait(pending.keys(), return_when=FIRST_COMPLETED)
                for fut in done_futs:
                    idx, p = pending.pop(fut)
                    try:
                        r = fut.result()
                        slots[idx - 1] = r
                        logger.info(
                            "batch_item_done",
                            extra={
                                "input": str(p),
                                "idx": idx,
                                "total": total,
                                "status": r.status,
                                "output_archive": str(r.output_archive) if r.output_archive else None,
                            },
                        )
                    except Exception as exc:  # noqa: BLE001
                        logger.exception(
                            "batch_item_failed",
                            extra={
                                "input": str(p),
                                "idx": idx,
                                "total": total,
                                "error": str(exc),
                            },
                        )
                        slots[idx - 1] = BatchItemResult(
                            index=idx,
                            input_path=p,
                            status="failed",
                            output_dir=(batch_dir / f"{idx:03d}-{_safe_output_component(p.name)}").resolve(),
                            error=f"{type(exc).__name__}: {exc}",
                        )
                    done += 1
                    if progress is not None:
                        progress.emit(
                            now_event(
                                kind=ProgressKind.STAGE_PROGRESS,
                                stage=ProgressStage.PROCESSING,
                                current=done,
                                total=total,
                                message=f"input={p.name}",
                            )
                        )

    normalized: list[BatchItemResult] = []
    for idx, (p, slot) in enumerate(zip(inputs, slots, strict=True), start=1):
        if slot is None:
            normalized.append(
                BatchItemResult(
                    index=idx,
                    input_path=p,
                    status="failed",
                    output_dir=batch_dir,
                    error="missing_result",
                )
            )
        else:
            normalized.append(slot)

    summary_path = (batch_dir / "batch_summary.json").resolve()

    def _result_to_jsonable(r: ProcessorResult) -> dict[str, object]:
        return {
            "output_zip": str(r.output_zip),
            "total_files": int(r.total_files),
            "processed_files": int(r.processed_files),
            "failed_files": int(r.failed_files),
            "excluded_files": int(r.excluded_files),
            "profiling_report_path": str(r.profiling_report_path) if r.profiling_report_path else None,
            "suggested_rules_path": str(r.suggested_rules_path) if r.suggested_rules_path else None,
            "cancelled": bool(r.cancelled),
            "rolled_back": bool(r.rolled_back),
        }

    summary_obj = {
        "batch_dir": str(batch_dir),
        "items": [
            {
                "index": int(it.index),
                "input_path": str(it.input_path),
                "status": it.status,
                "output_dir": str(it.output_dir),
                "output_archive": str(it.output_archive) if it.output_archive else None,
                "error": it.error,
                "result": _result_to_jsonable(it.result) if it.result is not None else None,
            }
            for it in normalized
        ],
        "summary": {
            "total": len(normalized),
            "succeeded": sum(1 for it in normalized if it.status == "success"),
            "failed": sum(1 for it in normalized if it.status == "failed"),
            "cancelled": sum(1 for it in normalized if it.status == "cancelled"),
            "skipped": sum(1 for it in normalized if it.status == "skipped"),
        },
    }
    summary_path.write_text(json.dumps(summary_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if progress is not None:
        progress.emit(
            now_event(
                kind=ProgressKind.STAGE_END,
                stage=ProgressStage.PROCESSING,
                current=len(normalized),
                total=total,
                message="batch_done",
            )
        )

    logger.info(
        "batch_done",
        extra={
            "batch_dir": str(batch_dir),
            "summary_path": str(summary_path),
            "total": len(normalized),
            "succeeded": sum(1 for it in normalized if it.status == "success"),
            "failed": sum(1 for it in normalized if it.status == "failed"),
            "cancelled": sum(1 for it in normalized if it.status == "cancelled"),
            "skipped": sum(1 for it in normalized if it.status == "skipped"),
        },
    )
    return BatchResult(batch_dir=batch_dir, items=normalized, summary_path=summary_path)
