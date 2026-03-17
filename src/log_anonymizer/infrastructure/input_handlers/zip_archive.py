from __future__ import annotations

import shutil
import tempfile
import zipfile
from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput


class ZipArchiveInputHandler:
    def prepare(self, input_path: Path) -> PreparedInput:
        zip_path = input_path.resolve()
        if not zip_path.is_file() or zip_path.suffix.lower() != ".zip":
            raise ValueError(f"Not a zip archive: {input_path}")

        tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-in-"))
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                _safe_extractall(zf, tmp_dir)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

        def _cleanup() -> None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return PreparedInput(root_dir=tmp_dir, only_relative=None, cleanup=_cleanup)


def _safe_extractall(zf: zipfile.ZipFile, dest: Path) -> None:
    """
    Protect against Zip Slip (path traversal) by ensuring every extracted member stays within `dest`.
    """
    dest_resolved = dest.resolve()
    for member in zf.infolist():
        member_path = (dest / member.filename).resolve()
        if dest_resolved not in member_path.parents and member_path != dest_resolved:
            raise ValueError(f"Unsafe zip member path: {member.filename}")
        zf.extract(member, dest)
