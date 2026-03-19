from __future__ import annotations

import gzip
import logging
import shutil
import tarfile
import tempfile
from pathlib import Path

from log_anonymizer.infrastructure.input_handlers.base import PreparedInput

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

    try:
        with tarfile.open(
            tar_gz_path,
            mode="r:gz",
            ignore_zeros=True,
            errorlevel=0,
        ) as tf:
            _extract_tar_streaming_from_tarfile(
                tf, tar_gz_path=tar_gz_path, dest=dest, dest_resolved=dest_resolved
            )
            return
    except (EOFError, gzip.BadGzipFile, tarfile.ReadError) as exc:
        raise ValueError(
            f"Invalid .tar.gz archive (corrupted or truncated): {tar_gz_path}"
        ) from exc


def _extract_tar_streaming_from_tarfile(
    tf: tarfile.TarFile,
    *,
    tar_gz_path: Path,
    dest: Path,
    dest_resolved: Path,
) -> bool:
    extracted_any = False

    while True:
        try:
            member = tf.next()
        except EOFError as exc:
            raise EOFError(f"Unexpected EOF while reading tar members: {tar_gz_path}") from exc
        except tarfile.ReadError as exc:
            raise tarfile.ReadError(f"Error while reading tar members: {tar_gz_path}") from exc

        if member is None:
            break
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
        try:
            src = tf.extractfile(member)
        except tarfile.ExtractError as exc:
            raise tarfile.ExtractError(f"Failed extracting member {name} from {tar_gz_path}") from exc
        except EOFError as exc:
            raise EOFError(f"Unexpected EOF extracting member {name} from {tar_gz_path}") from exc
        if src is None:
            continue

        with src:
            with member_path.open("wb") as dst:
                while True:
                    try:
                        chunk = src.read(1024 * 1024)
                    except EOFError as exc:
                        raise EOFError(
                            f"Unexpected EOF reading member {name} from {tar_gz_path}"
                        ) from exc
                    if not chunk:
                        break
                    dst.write(chunk)
                    extracted_any = True

    return extracted_any
