from __future__ import annotations

from pathlib import Path

from log_anonymizer.anonymizer import anonymize_file
from log_anonymizer.processor import ProcessorConfig, process_with_result
from log_anonymizer.progress import (
    ListProgressReporter,
    ProgressKind,
    ProgressStage,
)


def test_processor_emits_stage_and_file_events_sequential(tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "a.log").write_text("user=bob ip 10.0.0.1\n", encoding="utf-8")
    (inp / "b.bin").write_bytes(b"\x00\x01\x02binary")
    # Excluded by default patterns (*.keytab)
    (inp / "secret.keytab").write_bytes(b"\x00\x01\x02")

    out_dir = tmp_path / "out"
    reporter = ListProgressReporter()
    res = process_with_result(
        input_path=inp,
        rules_path=None,
        output_dir=out_dir,
        config=ProcessorConfig(parallel_enabled=False),
        progress=reporter,
    )
    assert res.output_zip.exists()

    kinds = [e.kind for e in reporter.events]
    assert ProgressKind.STAGE_START in kinds
    assert ProgressKind.STAGE_END in kinds

    stage_starts = [e for e in reporter.events if e.kind == ProgressKind.STAGE_START]
    assert any(e.stage == ProgressStage.DISCOVERY for e in stage_starts)
    assert any(e.stage == ProgressStage.FILTERING for e in stage_starts)
    assert any(e.stage == ProgressStage.PROCESSING for e in stage_starts)
    assert any(e.stage == ProgressStage.ARCHIVE for e in stage_starts)
    assert any(e.stage == ProgressStage.FINISHED for e in stage_starts)

    proc_start = next(
        e
        for e in reporter.events
        if e.kind == ProgressKind.STAGE_START and e.stage == ProgressStage.PROCESSING
    )
    assert proc_start.total == 2  # a.log + b.bin (keytab excluded)

    proc_progress = [
        e
        for e in reporter.events
        if e.kind == ProgressKind.STAGE_PROGRESS and e.stage == ProgressStage.PROCESSING
    ]
    assert proc_progress and proc_progress[-1].current == 2

    file_starts = [
        e for e in reporter.events if e.kind == ProgressKind.FILE_START and e.stage == ProgressStage.PROCESSING
    ]
    file_ends = [
        e for e in reporter.events if e.kind == ProgressKind.FILE_END and e.stage == ProgressStage.PROCESSING
    ]
    assert {e.path for e in file_starts} == {"a.log", "b.bin"}
    assert {e.path for e in file_ends} == {"a.log", "b.bin"}


def test_processor_emits_events_parallel(tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    for i in range(6):
        (inp / f"{i}.log").write_text(f"user=u{i}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    reporter = ListProgressReporter()
    _ = process_with_result(
        input_path=inp,
        rules_path=None,
        output_dir=out_dir,
        config=ProcessorConfig(parallel_enabled=True, max_workers=3),
        progress=reporter,
    )

    proc_start = next(
        e
        for e in reporter.events
        if e.kind == ProgressKind.STAGE_START and e.stage == ProgressStage.PROCESSING
    )
    assert proc_start.total == 6

    proc_progress = [
        e
        for e in reporter.events
        if e.kind == ProgressKind.STAGE_PROGRESS and e.stage == ProgressStage.PROCESSING
    ]
    assert proc_progress and proc_progress[-1].current == 6


def test_anonymize_file_can_emit_fine_grained_file_progress(tmp_path: Path) -> None:
    inp = tmp_path / "in.log"
    inp.write_text("x\n" * 2000, encoding="utf-8")
    outp = tmp_path / "out.log"

    reporter = ListProgressReporter()
    _ = anonymize_file(
        inp,
        outp,
        rules=[],
        progress=reporter,
        rel_path="in.log",
        progress_min_bytes=1,
        progress_min_interval_s=0.0,
    )

    assert any(e.kind == ProgressKind.FILE_PROGRESS for e in reporter.events)

