from __future__ import annotations

import logging
import shutil
import tarfile
import tempfile
from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput
from log_anonymizer.utils.io import is_text_bytes

logger = logging.getLogger(__name__)


class TarGzArchiveInputHandler:
    def prepare(self, input_path: Path) -> PreparedInput:
        tar_path = input_path.resolve()
        if not tar_path.is_file() or not _is_tar_gz(tar_path):
            raise ValueError(f"Not a tar.gz archive: {input_path}")

        tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-in-"))
        try:
            _safe_extract_tar_gz(tar_path, tmp_dir)
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

        def _cleanup() -> None:
            shutil.rmtree(tmp_dir, ignore_errors=True)

        return PreparedInput(root_dir=tmp_dir, only_relative=None, cleanup=_cleanup)


def _is_tar_gz(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tar.gz") or name.endswith(".tgz")


def _safe_extract_tar_gz(tar_gz_path: Path, dest: Path) -> None:
    """
    Protect against Tar Slip (path traversal) by ensuring every extracted member stays within `dest`.

    Only extracts regular files; skips symlinks/hardlinks/devices.
    """
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()

    with tarfile.open(tar_gz_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isdir():
                continue
            if not member.isreg():
                continue

            name = member.name
            if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                raise ValueError(f"Unsafe tar member path: {name}")

            member_path = (dest / name).resolve()
            if dest_resolved not in member_path.parents and member_path != dest_resolved:
                raise ValueError(f"Unsafe tar member path: {name}")

            member_path.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                head = src.read(8192)
                if not is_text_bytes(head):
                    logger.info("Skipping non-text file: %s", tar_gz_path / name)
                    continue
                with member_path.open("wb") as dst:
                    dst.write(head)
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
