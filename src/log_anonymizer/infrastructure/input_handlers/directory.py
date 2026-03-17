from __future__ import annotations

from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput


class DirectoryInputHandler:
    def prepare(self, input_path: Path) -> PreparedInput:
        root_dir = input_path.resolve()
        if not root_dir.is_dir():
            raise ValueError(f"Not a directory: {input_path}")

        return PreparedInput(root_dir=root_dir, only_relative=None, cleanup=lambda: None)

