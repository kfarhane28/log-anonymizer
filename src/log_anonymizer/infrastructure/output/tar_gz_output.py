from __future__ import annotations

import shutil
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TarGzOutputManager:
    output_tar_gz_path: Path

    def __post_init__(self) -> None:
        self._tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-out-"))

    @property
    def root_dir(self) -> Path:
        return self._tmp_dir

    def close(self) -> None:
        self._write_tar_gz(self._tmp_dir, self.output_tar_gz_path)
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def __enter__(self) -> "TarGzOutputManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if exc_type is not None:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            return
        self.close()

    @staticmethod
    def _write_tar_gz(root: Path, out_tar_gz: Path) -> None:
        out_tar_gz.parent.mkdir(parents=True, exist_ok=True)
        if out_tar_gz.exists():
            out_tar_gz.unlink()
        with tarfile.open(out_tar_gz, mode="w:gz") as tf:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                tf.add(path, arcname=rel, recursive=False)

