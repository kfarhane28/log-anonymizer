from __future__ import annotations

import logging
import shutil
import tempfile
import tarfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from log_anonymizer.utils.io import is_text_bytes, is_text_file

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class InputHandlingResult:
    """
    Result of preparing an input for processing.

    Attributes:
        working_dir: Directory that contains the returned files. For a directory input,
            this is the input directory. For a single-file input, this is the file's
            parent directory. For a zip input, this is a temporary extraction directory.
        files: Absolute file paths to process.
    """

    working_dir: Path
    files: list[Path]


@contextmanager
def handle_input(input_path: Path) -> Iterator[InputHandlingResult]:
    """
    Prepare an input path (directory, file, or archive) for processing.

    Responsibilities:
    - Detect input type automatically.
    - If directory: recursively list all files.
    - If file: treat as a single file.
    - If archive (.zip / .tar.gz / .tgz): safely extract to a temporary directory and recursively list extracted files.

    Returns:
        A context manager yielding an InputHandlingResult. Temporary directories created
        for archive inputs are cleaned up automatically on exit.

    Notes:
        For very large archives, a streaming approach (reading zip members without full
        extraction) can be more efficient, but most anonymization pipelines expect
        file paths. This implementation extracts in a safe, streaming manner (member
        by member) to avoid loading whole files into memory.
    """
    resolved = input_path.expanduser().resolve()
    if not resolved.exists():
        raise FileNotFoundError(resolved)

    tmp_dir: Path | None = None
    try:
        if resolved.is_dir():
            logger.info("input_detected", extra={"type": "directory", "path": str(resolved)})
            files = list(_iter_files(resolved))
            logger.info("input_files_listed", extra={"count": len(files)})
            yield InputHandlingResult(working_dir=resolved, files=files)
            return

        if resolved.is_file() and resolved.suffix.lower() == ".zip":
            logger.info("input_detected", extra={"type": "zip", "path": str(resolved)})
            tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-input-")).resolve()
            logger.debug("zip_extract_start", extra={"zip": str(resolved), "tmp_dir": str(tmp_dir)})
            _extract_zip_streaming(resolved, tmp_dir)
            files = list(_iter_files(tmp_dir))
            logger.info("input_files_listed", extra={"count": len(files), "working_dir": str(tmp_dir)})
            yield InputHandlingResult(working_dir=tmp_dir, files=files)
            return

        if resolved.is_file() and _is_tar_gz(resolved):
            logger.info("input_detected", extra={"type": "tar.gz", "path": str(resolved)})
            tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-input-")).resolve()
            logger.debug(
                "tar_extract_start",
                extra={"tar": str(resolved), "tmp_dir": str(tmp_dir)},
            )
            _extract_tar_gz_streaming(resolved, tmp_dir)
            files = list(_iter_files(tmp_dir))
            logger.info("input_files_listed", extra={"count": len(files), "working_dir": str(tmp_dir)})
            yield InputHandlingResult(working_dir=tmp_dir, files=files)
            return

        if resolved.is_file():
            logger.info("input_detected", extra={"type": "file", "path": str(resolved)})
            if not is_text_file(resolved):
                logger.info("Skipping non-text file: %s", resolved)
                yield InputHandlingResult(working_dir=resolved.parent, files=[])
                return
            yield InputHandlingResult(working_dir=resolved.parent, files=[resolved])
            return

        raise ValueError(f"Unsupported input path: {resolved}")
    finally:
        if tmp_dir is not None:
            logger.debug("cleanup_tmp_dir", extra={"tmp_dir": str(tmp_dir)})
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _iter_files(root_dir: Path) -> Iterator[Path]:
    """
    Recursively yield file paths under root_dir.

    Uses an explicit stack to avoid recursion depth issues on deeply nested trees.
    Skips symlinks to avoid potential cycles.
    """
    stack: list[Path] = [root_dir]
    while stack:
        current = stack.pop()
        try:
            for entry in current.iterdir():
                # Avoid following symlinks in support bundles.
                if entry.is_symlink():
                    logger.debug("skip_symlink", extra={"path": str(entry)})
                    continue
                if entry.is_dir():
                    stack.append(entry)
                elif entry.is_file():
                    if not is_text_file(entry):
                        logger.info("Skipping non-text file: %s", entry)
                        continue
                    logger.debug("discovered_file", extra={"path": str(entry)})
                    yield entry
        except OSError as exc:
            logger.debug("skip_unreadable_dir", extra={"path": str(current), "reason": str(exc)})


def _extract_zip_streaming(zip_path: Path, dest_dir: Path) -> None:
    """
    Extract `zip_path` into `dest_dir` in a safe, streaming way.

    - Defends against Zip Slip (path traversal)
    - Streams each member to disk (does not load whole members into memory)
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            # Skip directories; they will be created as needed.
            if info.is_dir():
                continue

            target = (dest_dir / info.filename).resolve()
            if dest_root not in target.parents and target != dest_root:
                raise ValueError(f"Unsafe zip member path: {info.filename}")

            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src:
                head = src.read(8192)
                if not is_text_bytes(head):
                    logger.info("Skipping non-text file: %s", zip_path / info.filename)
                    continue
                with target.open("wb") as dst:
                    dst.write(head)
                    shutil.copyfileobj(src, dst, length=1024 * 1024)


def _is_tar_gz(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tar.gz") or name.endswith(".tgz")


def _extract_tar_gz_streaming(tar_gz_path: Path, dest_dir: Path) -> None:
    """
    Extract `tar_gz_path` into `dest_dir` in a safe, streaming way.

    - Defends against Tar Slip (path traversal)
    - Only extracts regular files (skips symlinks, hardlinks, devices, etc.)
    - Streams each member to disk (does not load whole members into memory)
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    with tarfile.open(tar_gz_path, mode="r:gz") as tf:
        for member in tf.getmembers():
            if member.isdir():
                continue
            if not member.isreg():
                logger.debug(
                    "skip_non_regular_tar_member",
                    extra={"member": member.name, "type": member.type},
                )
                continue

            name = member.name
            # Basic sanity: reject absolute paths and traversal.
            if name.startswith(("/", "\\")) or ".." in Path(name).parts:
                raise ValueError(f"Unsafe tar member path: {name}")

            target = (dest_dir / name).resolve()
            if dest_root not in target.parents and target != dest_root:
                raise ValueError(f"Unsafe tar member path: {name}")

            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src:
                head = src.read(8192)
                if not is_text_bytes(head):
                    logger.info("Skipping non-text file: %s", tar_gz_path / name)
                    continue
                with target.open("wb") as dst:
                    dst.write(head)
                    shutil.copyfileobj(src, dst, length=1024 * 1024)
