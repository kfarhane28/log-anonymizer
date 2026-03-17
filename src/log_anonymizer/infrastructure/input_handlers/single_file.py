from __future__ import annotations

from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput
from log_anonymizer.utils.paths import as_posix_relpath


class SingleFileInputHandler:
    def prepare(self, input_path: Path) -> PreparedInput:
        file_path = input_path.resolve()
        if not file_path.is_file():
            raise ValueError(f"Not a file: {input_path}")

        root_dir = file_path.parent
        only_relative = as_posix_relpath(file_path, root_dir)
        return PreparedInput(
            root_dir=root_dir, only_relative=only_relative, cleanup=lambda: None
        )

