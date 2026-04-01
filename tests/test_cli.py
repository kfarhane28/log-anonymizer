from __future__ import annotations

from log_anonymizer import cli


def test_cli_accepts_anonymize_filenames_flag() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "--input",
            "in",
            "--output",
            "out",
            "--rules",
            "rules.json",
            "--anonymize-filenames",
        ]
    )
    assert bool(args.anonymize_filenames) is True
    assert [str(p) for p in args.inputs] == ["in"]


def test_cli_accepts_multiple_inputs() -> None:
    parser = cli._build_parser()
    args = parser.parse_args(
        [
            "--input",
            "in1",
            "--input",
            "in2.zip",
            "--output",
            "out",
            "--rules",
            "rules.json",
        ]
    )
    assert [str(p) for p in args.inputs] == ["in1", "in2.zip"]
