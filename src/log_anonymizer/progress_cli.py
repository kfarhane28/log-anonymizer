from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass
from queue import Empty, Queue
from typing import TextIO

from log_anonymizer.progress import ProgressEvent, ProgressKind, ProgressStage, ProgressStopToken


@dataclass
class _CliProgressState:
    stage: ProgressStage | None = None
    stage_current: int | None = None
    stage_total: int | None = None
    stage_message: str | None = None
    last_file_path: str | None = None
    last_file_done: int | None = None
    last_file_total: int | None = None
    last_render: float = 0.0


def start_cli_progress_thread(
    q: Queue[ProgressEvent],
    stop: ProgressStopToken,
    *,
    stream: TextIO | None = None,
    min_render_interval_s: float = 0.1,
) -> threading.Thread:
    """
    Consume ProgressEvent from `q` and render a single-line progress indicator to `stream`.

    Rendering goes to stderr by default to avoid corrupting stdout output (logs / final path).
    """
    out = stream or sys.stderr
    state = _CliProgressState()

    def _render(force_newline: bool = False) -> None:
        now = time.monotonic()
        if not force_newline and (now - state.last_render) < min_render_interval_s:
            return
        state.last_render = now

        if state.stage is None:
            return

        stage = state.stage.value
        if state.stage_total is not None and state.stage_current is not None:
            pct = (
                int(100 * state.stage_current / state.stage_total)
                if state.stage_total > 0
                else 100
            )
            head = f"{stage}: {state.stage_current}/{state.stage_total} ({pct}%)"
        elif state.stage_current is not None:
            head = f"{stage}: {state.stage_current}"
        else:
            head = f"{stage}"

        tail_parts: list[str] = []
        if state.stage_message:
            tail_parts.append(state.stage_message)

        if (
            state.last_file_path
            and state.last_file_done is not None
            and state.last_file_total is not None
            and state.last_file_total > 0
        ):
            fpct = int(100 * state.last_file_done / state.last_file_total)
            tail_parts.append(f"file={state.last_file_path} {fpct}%")
        elif state.last_file_path:
            tail_parts.append(f"file={state.last_file_path}")

        line = head
        if tail_parts:
            line += " | " + " ".join(tail_parts)

        # Clear line with padding (best effort).
        pad = " " * 20
        out.write("\r" + line + pad)
        out.flush()

        if force_newline:
            out.write("\n")
            out.flush()

    def _loop() -> None:
        last_stage: ProgressStage | None = None
        while True:
            if stop.is_stopped() and q.empty():
                break
            try:
                ev = q.get(timeout=0.1)
            except Empty:
                _render()
                continue

            if ev.kind in (ProgressKind.STAGE_START, ProgressKind.STAGE_PROGRESS, ProgressKind.STAGE_END):
                state.stage = ev.stage
                state.stage_current = ev.current
                state.stage_total = ev.total
                state.stage_message = ev.message
                if ev.kind == ProgressKind.STAGE_START:
                    state.last_file_path = None
                    state.last_file_done = None
                    state.last_file_total = None

            if ev.kind == ProgressKind.FILE_START:
                state.last_file_path = ev.path
                state.last_file_done = ev.bytes_done
                state.last_file_total = ev.bytes_total

            if ev.kind == ProgressKind.FILE_PROGRESS:
                state.last_file_path = ev.path
                state.last_file_done = ev.bytes_done
                state.last_file_total = ev.bytes_total

            if ev.kind == ProgressKind.FILE_END:
                # Keep last file path for context; mark as complete if size known.
                state.last_file_path = ev.path
                if ev.bytes_total is not None:
                    state.last_file_done = ev.bytes_total
                    state.last_file_total = ev.bytes_total

            if ev.stage != last_stage and last_stage is not None:
                _render(force_newline=True)
            last_stage = ev.stage

            if ev.kind == ProgressKind.STAGE_END and ev.stage in (ProgressStage.ARCHIVE, ProgressStage.PROCESSING):
                _render(force_newline=True)
            else:
                _render()

        _render(force_newline=True)

    t = threading.Thread(target=_loop, name="cli-progress", daemon=True)
    t.start()
    return t

