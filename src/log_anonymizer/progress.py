from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from enum import Enum
from queue import Full, Queue
from typing import Protocol


class ProgressStage(str, Enum):
    DISCOVERY = "discovery"
    FILTERING = "filtering"
    PROCESSING = "processing"
    ARCHIVE = "archive"
    FINISHED = "finished"


class ProgressKind(str, Enum):
    STAGE_START = "stage_start"
    STAGE_PROGRESS = "stage_progress"
    STAGE_END = "stage_end"
    FILE_START = "file_start"
    FILE_PROGRESS = "file_progress"
    FILE_END = "file_end"


@dataclass(frozen=True)
class ProgressEvent:
    kind: ProgressKind
    stage: ProgressStage
    ts_monotonic: float
    current: int | None = None
    total: int | None = None
    path: str | None = None  # POSIX relative path when available
    bytes_done: int | None = None
    bytes_total: int | None = None
    ok: bool | None = None
    message: str | None = None


class ProgressReporter(Protocol):
    def emit(self, event: ProgressEvent) -> None: ...


class NullProgressReporter:
    def emit(self, event: ProgressEvent) -> None:  # noqa: ARG002
        return


class ListProgressReporter:
    """
    Simple in-memory reporter (useful for tests).
    """

    def __init__(self) -> None:
        self.events: list[ProgressEvent] = []

    def emit(self, event: ProgressEvent) -> None:
        self.events.append(event)


class QueueProgressReporter:
    """
    Thread-safe reporter that pushes events to a Queue.

    To limit overhead, FILE_PROGRESS events are dropped if the queue is full.
    """

    def __init__(self, q: Queue[ProgressEvent], *, drop_when_full: bool = True) -> None:
        self._q = q
        self._drop_when_full = drop_when_full

    def emit(self, event: ProgressEvent) -> None:
        if not self._drop_when_full:
            self._q.put(event)
            return
        try:
            self._q.put_nowait(event)
        except Full:
            if event.kind != ProgressKind.FILE_PROGRESS:
                # Best effort: block for non-spammy events.
                try:
                    self._q.put(event, timeout=0.5)
                except Full:
                    return


class ProgressStopToken:
    def __init__(self) -> None:
        self._ev = threading.Event()

    def stop(self) -> None:
        self._ev.set()

    def is_stopped(self) -> bool:
        return self._ev.is_set()


def now_event(
    *,
    kind: ProgressKind,
    stage: ProgressStage,
    current: int | None = None,
    total: int | None = None,
    path: str | None = None,
    bytes_done: int | None = None,
    bytes_total: int | None = None,
    ok: bool | None = None,
    message: str | None = None,
) -> ProgressEvent:
    return ProgressEvent(
        kind=kind,
        stage=stage,
        ts_monotonic=time.monotonic(),
        current=current,
        total=total,
        path=path,
        bytes_done=bytes_done,
        bytes_total=bytes_total,
        ok=ok,
        message=message,
    )

