from __future__ import annotations

import tarfile
import zipfile
import hashlib
from pathlib import Path

import pytest

from log_anonymizer.input_handler import handle_input
from log_anonymizer.processor import process_with_result


def test_handle_input_supports_tar_gz(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "a").mkdir()
    (src_dir / "a" / "b.log").write_text("hello\n", encoding="utf-8")
    (src_dir / "a" / "c.pdf").write_bytes(b"%PDF-1.7\n%binary\n\xff\x00\x10\n")

    tar_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_path, mode="w:gz") as tf:
        tf.add(src_dir, arcname="bundle", recursive=True)

    with handle_input(tar_path) as prepared:
        files = {p.name: p for p in prepared.files}
        assert files["b.log"].read_text(encoding="utf-8") == "hello\n"
        assert files["c.pdf"].read_bytes().startswith(b"%PDF-1.7")


def test_handle_input_best_effort_for_truncated_tar_gz(tmp_path: Path) -> None:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    # Generate mostly-incompressible (but valid UTF-8) content so truncating the
    # archive tail simulates a realistic "missing end bytes" scenario without
    # destroying the beginning of the gzip stream.
    seed = b"0"
    lines: list[str] = []
    for _ in range(4000):
        seed = hashlib.sha256(seed).digest()
        lines.append(seed.hex())
    (src_dir / "x.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    tar_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_path, mode="w:gz") as tf:
        tf.add(src_dir, arcname="bundle", recursive=True)

    data = tar_path.read_bytes()
    truncated = tmp_path / "bundle-truncated.tar.gz"
    truncated.write_bytes(data[:-100])

    with handle_input(truncated) as prepared:
        files = [p for p in prepared.files if p.name == "x.log"]
        assert len(files) == 1
        extracted = files[0].read_text(encoding="utf-8")
        assert extracted == "" or extracted.startswith(lines[0])


def test_processor_outputs_tar_gz_and_rules_optional(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "x.log").write_text("no secrets here\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir)
    assert res.output_zip.exists()
    assert res.output_zip.name.endswith(".tar.gz")
    assert res.output_zip.parent == out_dir.resolve()
    assert res.output_zip.name == "in.tar.gz"

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        names = tf.getnames()
    assert "x.log" in names
    assert not (out_dir / "x.log").exists()


def test_processor_accepts_zip_input_and_outputs_tar_gz(tmp_path: Path) -> None:
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("dir/y.log", "hi\n")
        zf.writestr("dir/z.pdf", b"%PDF-1.7\n%binary\n\xff\x00\x10\n")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=zip_path, rules_path=None, output_dir=out_dir)
    assert res.output_zip.exists()
    assert res.output_zip.name.endswith(".tar.gz")
    assert res.output_zip.parent == out_dir.resolve()
    assert res.output_zip.name == "bundle.tar.gz"

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        names = tf.getnames()
    assert "dir/y.log" in names
    assert "dir/z.pdf" in names


def test_processor_ignores_non_text_in_directory(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "x.log").write_text("user=bob\n", encoding="utf-8")
    (inp_dir / "doc.pdf").write_bytes(b"%PDF-1.7\n%binary\n\xff\x00\x10\n")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir)

    assert not (out_dir / "x.log").exists()
    assert not (out_dir / "doc.pdf").exists()
    assert res.output_zip.name == "in.tar.gz"

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        names = tf.getnames()
    assert "x.log" in names
    assert "doc.pdf" in names


def test_processor_excludes_default_sensitive_patterns(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "x.log").write_text("ok\n", encoding="utf-8")
    (inp_dir / "krb5.conf").write_text("[libdefaults]\n", encoding="utf-8")
    (inp_dir / "user.keytab").write_bytes(b"\x00\x01\x02\x03binary")

    out_dir = tmp_path / "out"
    res = process_with_result(input_path=inp_dir, rules_path=None, output_dir=out_dir)

    with tarfile.open(res.output_zip, mode="r:gz") as tf:
        names = tf.getnames()
    assert "x.log" in names
    assert "krb5.conf" not in names
    assert "user.keytab" not in names
