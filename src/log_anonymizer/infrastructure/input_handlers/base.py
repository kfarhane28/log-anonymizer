from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass(frozen=True)
class PreparedInput:
    root_dir: Path
    only_relative: str | None
    cleanup: callable


class InputHandler(Protocol):
    def prepare(self, input_path: Path) -> PreparedInput: ...

