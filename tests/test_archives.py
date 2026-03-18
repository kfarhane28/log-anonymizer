from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from log_anonymizer.input_handler import handle_input
from log_anonymizer.processor import process_with_result


def test_handle_input_supports_tar_gz(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a").mkdir()
    (src_dir / "a" / "b.log").write_text("hello\n", encoding="utf-8")

    tar_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_path, mode="w:gz") as tf:
        tf.add(src_dir, arcname="bundle", recursive=True)

    with handle_input(tar_path) as prepared:
        files = [p for p in prepared.files if p.name == "b.log"]
        assert len(files) == 1
        assert files[0].read_text(encoding="utf-8") == "hello\n"


def test_processor_outputs_tar_gz_and_rules_optional(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "x.log").write_text("no secrets here\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir)
    assert res.output_zip.exists()
    assert res.output_zip.name.endswith(".tar.gz")

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        names = tf.getnames()
    assert "x.log" in names
    assert (out_dir / "x.log").exists()


def test_processor_accepts_zip_input_and_outputs_tar_gz(tmp_path: Path) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dir/y.log", "hi\n")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=zip_path, rules_path=None, output_dir=out_dir)
    assert res.output_zip.exists()
    assert res.output_zip.name.endswith(".tar.gz")

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        assert "dir/y.log" in tf.getnames()

