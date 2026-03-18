from __future__ import annotations

import logging
import shutil
import tempfile
import zipfile
from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput
from log_anonymizer.utils.io import is_text_bytes

logger = logging.getLogger(__name__)


class ZipArchiveInputHandler:
    def prepare(self, input_path: Path) -> PreparedInput:
        zip_path = input_path.resolve()
        if not zip_path.is_file() or zip_path.suffix.lower() != ".zip":
            raise ValueError(f"Not a zip archive: {input_path}")

        tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-in-"))
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                _safe_extractall(zf, tmp_dir, archive_path=zip_path)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

        def _cleanup() -> None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return PreparedInput(root_dir=tmp_dir, only_relative=None, cleanup=_cleanup)


def _safe_extractall(zf: zipfile.ZipFile, dest: Path, *, archive_path: Path) -> None:
    """
    Protect against Zip Slip (path traversal) by ensuring every extracted member stays within `dest`.
    """
    dest_resolved = dest.resolve()
    for member in zf.infolist():
        if member.is_dir():
            continue
        member_path = (dest / member.filename).resolve()
        if dest_resolved not in member_path.parents and member_path != dest_resolved:
            raise ValueError(f"Unsafe zip member path: {member.filename}")

        member_path.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(member, "r") as src:
            head = src.read(8192)
            if not is_text_bytes(head):
                logger.info("Skipping non-text file: %s", archive_path / member.filename)
                continue
            with member_path.open("wb") as dst:
                dst.write(head)
                shutil.copyfileobj(src, dst, length=1024 * 1024)
