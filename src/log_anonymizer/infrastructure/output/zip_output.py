from __future__ import annotations

import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ZipOutputManager:
    output_zip_path: Path

    def __post_init__(self) -> None:
        self._tmp_dir = Path(tempfile.mkdtemp(prefix="log-anonymizer-out-"))

    @property
    def root_dir(self) -> Path:
        return self._tmp_dir

    def close(self) -> None:
        self._write_zip(self._tmp_dir, self.output_zip_path)
        shutil.rmtree(self._tmp_dir, ignore_errors=True)

    def __enter__(self) -> "ZipOutputManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        if exc_type is not None:
            shutil.rmtree(self._tmp_dir, ignore_errors=True)
            return
        self.close()

    @staticmethod
    def _write_zip(root: Path, out_zip: Path) -> None:
        out_zip.parent.mkdir(parents=True, exist_ok=True)
        if out_zip.exists():
            out_zip.unlink()
        with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in root.rglob("*"):
                if not path.is_file():
                    continue
                rel = path.relative_to(root).as_posix()
                zf.write(path, arcname=rel)

