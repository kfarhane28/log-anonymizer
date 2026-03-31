from __future__ import annotations

import json
import tarfile
from pathlib import Path

from log_anonymizer.processor import ProcessorConfig, process_with_result


def _write_rules(tmp_path: Path, *, rules: list[dict]) -> Path:
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"version": 1, "rules": rules}, indent=2) + "\n", encoding="utf-8")
    return p


def _tar_names(path: Path) -> list[str]:
    with tarfile.open(path, mode="r:gz") as tf:
        return tf.getnames()


def test_filename_anonymization_disabled_preserves_paths_and_archive_name(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "host123").mkdir()
    (inp_dir / "host123" / "user-bob.log").write_text("hello bob\n", encoding="utf-8")

    rules_path = _write_rules(
        tmp_path,
        rules=[
            {
                "description": "bob",
                "trigger": "bob",
                "search": r"bob",
                "replace": "USER",
                "caseSensitive": True,
            }
        ],
    )

    out_dir = tmp_path / "out"
    res = process_with_result(
        input_path=inp_dir,
        rules_path=rules_path,
        output_dir=out_dir,
        config=ProcessorConfig(include_builtin_rules=False, anonymize_filenames=False),
    )

    assert res.output_zip.name == "in.tar.gz"
    names = _tar_names(res.output_zip)
    assert "host123/user-bob.log" in names


def test_filename_anonymization_enabled_anonymizes_paths_and_sanitizes_archive_name(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "host123").mkdir()
    (inp_dir / "host123" / "user-bob.log").write_text("hello bob\n", encoding="utf-8")

    rules_path = _write_rules(
        tmp_path,
        rules=[
            {
                "description": "host",
                "trigger": "host",
                "search": r"host\d+",
                "replace": "HOST",
                "caseSensitive": False,
            },
            {
                "description": "bob",
                "trigger": "bob",
                "search": r"bob",
                "replace": "USER",
                "caseSensitive": False,
            },
        ],
    )

    out_dir = tmp_path / "out"
    res = process_with_result(
        input_path=inp_dir,
        rules_path=rules_path,
        output_dir=out_dir,
        config=ProcessorConfig(include_builtin_rules=False, anonymize_filenames=True),
    )

    # Archive name should not leak input naming when filename anonymization is enabled.
    assert res.output_zip.name == "anonymized_output.tar.gz"
    names = _tar_names(res.output_zip)
    assert "HOST/user-USER.log" in names


def test_filename_anonymization_preserves_extensions_and_resolves_collisions(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "alice.log").write_text("hi\n", encoding="utf-8")
    (inp_dir / "bob.log").write_text("hi\n", encoding="utf-8")

    rules_path = _write_rules(
        tmp_path,
        rules=[
            {
                "description": "names",
                "trigger": "",
                "search": r"alice|bob",
                "replace": "user",
                "caseSensitive": False,
            }
        ],
    )

    out_dir1 = tmp_path / "out1"
    res1 = process_with_result(
        input_path=inp_dir,
        rules_path=rules_path,
        output_dir=out_dir1,
        config=ProcessorConfig(include_builtin_rules=False, anonymize_filenames=True),
    )
    names1 = sorted(_tar_names(res1.output_zip))

    # Deterministic across runs for the same inputs (in a fresh output dir).
    out_dir2 = tmp_path / "out2"
    res2 = process_with_result(
        input_path=inp_dir,
        rules_path=rules_path,
        output_dir=out_dir2,
        config=ProcessorConfig(include_builtin_rules=False, anonymize_filenames=True),
    )
    names2 = sorted(_tar_names(res2.output_zip))
    assert names1 == names2

    # Both files should exist, and extensions should be preserved.
    log_names = [n for n in names1 if n.endswith(".log")]
    assert len(log_names) == 2
    assert len(set(log_names)) == 2
    assert any(n == "user.log" for n in log_names)
    assert any(n.startswith("user__") and n.endswith(".log") for n in log_names)


def test_filename_anonymization_sanitizes_invalid_characters(tmp_path: Path) -> None:
    inp_dir = tmp_path / "in"
    inp_dir.mkdir()
    (inp_dir / "host:123?.log").write_text("hi\n", encoding="utf-8")

    # Provide at least one rule so the processor accepts text-file anonymization.
    rules_path = _write_rules(
        tmp_path,
        rules=[
            {
                "description": "noop",
                "trigger": "does-not-match",
                "search": r"does-not-match",
                "replace": "x",
                "caseSensitive": True,
            }
        ],
    )

    out_dir = tmp_path / "out"
    res = process_with_result(
        input_path=inp_dir,
        rules_path=rules_path,
        output_dir=out_dir,
        config=ProcessorConfig(include_builtin_rules=False, anonymize_filenames=True),
    )

    names = _tar_names(res.output_zip)
    assert any(n.endswith(".log") for n in names)
    assert not any(":" in n or "?" in n for n in names)
