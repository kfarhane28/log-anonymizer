from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from log_anonymizer.processor import ProcessorConfig, process_with_result


def _tar_members_bytes(path: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with tarfile.open(path, mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile():
                continue
            f = tf.extractfile(m)
            assert f is not None
            with f:
                out[m.name] = f.read()
    return out


def test_default_is_sequential(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "a.log").write_text("user=bob\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    caplog.set_level("INFO")
    res = process_with_result(input_path=inp, rules_path=None, output_dir=out_dir)
    assert res.output_zip.exists()

    assert any(
        r.message == "parallel_mode_disabled" and getattr(r, "mode", None) == "sequential"
        for r in caplog.records
    )


def test_parallel_uses_default_workers_5(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    for i in range(8):
        (inp / f"{i}.log").write_text(f"user=u{i}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    caplog.set_level("INFO")
    cfg = ProcessorConfig(parallel_enabled=True)
    _ = process_with_result(input_path=inp, rules_path=None, output_dir=out_dir, config=cfg)

    assert any(
        r.message == "parallel_mode_enabled" and getattr(r, "max_workers", None) == 5
        for r in caplog.records
    )


def test_parallel_uses_custom_workers(caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    for i in range(4):
        (inp / f"{i}.log").write_text(f"user=u{i}\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    caplog.set_level("INFO")
    cfg = ProcessorConfig(parallel_enabled=True, max_workers=3)
    _ = process_with_result(input_path=inp, rules_path=None, output_dir=out_dir, config=cfg)

    assert any(
        r.message == "parallel_mode_enabled" and getattr(r, "max_workers", None) == 3
        for r in caplog.records
    )


def test_parallel_matches_sequential_output(tmp_path: Path) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "a.log").write_text("user=bob ip 10.0.0.1\n", encoding="utf-8")
    (inp / "doc.pdf").write_bytes(b"%PDF-1.7\n%binary\n")
    (inp / "krb.keytab").write_bytes(b"\x00\x01\x02binary")

    exclude = tmp_path / ".exclude"
    exclude.write_text("*.keytab\n", encoding="utf-8")

    out_seq = tmp_path / "out_seq"
    out_par = tmp_path / "out_par"

    seq = process_with_result(
        input_path=inp,
        rules_path=None,
        output_dir=out_seq,
        exclude_path=exclude,
        config=ProcessorConfig(parallel_enabled=False),
    )
    par = process_with_result(
        input_path=inp,
        rules_path=None,
        output_dir=out_par,
        exclude_path=exclude,
        config=ProcessorConfig(parallel_enabled=True, max_workers=3),
    )

    seq_members = _tar_members_bytes(seq.output_zip)
    par_members = _tar_members_bytes(par.output_zip)
    assert seq_members == par_members
    assert "doc.pdf" in seq_members
    assert "krb.keytab" not in seq_members


def test_parallel_continues_on_single_file_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    inp = tmp_path / "in"
    inp.mkdir()
    (inp / "ok.log").write_text("user=bob\n", encoding="utf-8")
    (inp / "bad.log").write_text("user=alice\n", encoding="utf-8")
    out_dir = tmp_path / "out"

    import log_anonymizer.processor as processor

    real = processor.anonymize_file

    def boom(src: Path, dest: Path, rules):  # noqa: ANN001
        if src.name == "bad.log":
            raise OSError("boom")
        return real(src, dest, rules)

    monkeypatch.setattr(processor, "anonymize_file", boom)

    res = process_with_result(
        input_path=inp,
        rules_path=None,
        output_dir=out_dir,
        config=ProcessorConfig(parallel_enabled=True, max_workers=2),
    )
    members = _tar_members_bytes(res.output_zip)
    assert "ok.log" in members
