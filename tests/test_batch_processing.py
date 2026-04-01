from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from log_anonymizer.batch import process_batch_with_result
from log_anonymizer.processor import ProcessorConfig


def test_batch_processes_mixed_inputs_and_writes_isolated_outputs(tmp_path: Path) -> None:
    # 1) Directory input
    inp_dir = tmp_path / "dir_in"
    inp_dir.mkdir()
    (inp_dir / "a.log").write_text("user=bob\n", encoding="utf-8")

    # 2) Single file input
    inp_file = tmp_path / "single.log"
    inp_file.write_text("ip=10.0.0.1\n", encoding="utf-8")

    # 3) Zip archive input
    zip_path = tmp_path / "bundle.zip"
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("nested/x.log", "token=secret\n")

    out_dir = tmp_path / "out"
    batch = process_batch_with_result(
        inputs=[inp_dir, inp_file, zip_path],
        rules_path=None,
        output_dir=out_dir,
        config=ProcessorConfig(),
        batch_parallel_enabled=True,
        batch_max_workers=3,
        batch_dir_name="batch-test",
    )

    assert batch.batch_dir == (out_dir / "batch-test").resolve()
    assert batch.summary_path.exists()
    assert len(batch.items) == 3
    assert all(it.status == "success" for it in batch.items)

    # Ensure output dirs are unique and each produced an archive.
    output_dirs = {it.output_dir for it in batch.items}
    assert len(output_dirs) == 3
    for it in batch.items:
        assert it.output_archive is not None
        assert it.output_archive.exists()
        assert it.output_archive.parent == it.output_dir
        assert it.output_dir.parent == batch.batch_dir


def test_batch_failure_is_isolated_to_one_input(tmp_path: Path) -> None:
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    (good_dir / "ok.log").write_text("hello\n", encoding="utf-8")

    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "x.log").write_text("hello\n", encoding="utf-8")
    tar_path = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_path, mode="w:gz") as tf:
        tf.add(src_dir, arcname="bundle", recursive=True)
    truncated = tmp_path / "bundle-truncated.tar.gz"
    truncated.write_bytes(tar_path.read_bytes()[:-100])

    out_dir = tmp_path / "out"
    batch = process_batch_with_result(
        inputs=[good_dir, truncated],
        rules_path=None,
        output_dir=out_dir,
        config=ProcessorConfig(),
        batch_parallel_enabled=False,
        batch_dir_name="batch-failure",
    )

    assert batch.summary_path.exists()
    assert len(batch.items) == 2
    statuses = [it.status for it in batch.items]
    assert "success" in statuses
    assert "failed" in statuses

    ok_items = [it for it in batch.items if it.status == "success"]
    assert len(ok_items) == 1
    assert ok_items[0].output_archive is not None
    assert ok_items[0].output_archive.exists()

