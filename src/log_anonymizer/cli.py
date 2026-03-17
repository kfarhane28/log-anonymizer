from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from typing import NoReturn

from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.config.logging_config import LogFormat, setup_logging
from log_anonymizer.exclude_filter import ExcludeFilter
from log_anonymizer.input_handler import handle_input
from log_anonymizer.processor import ProcessorConfig, process
from log_anonymizer.rules_loader import load_rules


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-anonymizer",
        description="Anonymize Hadoop/Cloudera logs (directory, file, or zip). Writes anonymized logs to an output directory and produces a zip archive.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Input path (directory, single file, or .zip archive).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Output directory for anonymized logs.",
    )
    parser.add_argument(
        "--rules",
        "-r",
        type=Path,
        required=True,
        help="Rules JSON file.",
    )
    parser.add_argument(
        "--exclude",
        "-x",
        type=Path,
        default=None,
        help="Optional .exclude file with glob patterns.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate and report what would be processed without writing output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging.")
    parser.add_argument("--exclude-case-insensitive", action="store_true", help="Case-insensitive exclude matching.")
    parser.add_argument("--no-default-rules", action="store_true", help="Do not include built-in Hadoop-sensitive rules.")
    parser.add_argument(
        "--log-level",
        default="INFO",
        help="Logging level (default: INFO).",
    )
    parser.add_argument(
        "--log-format",
        choices=[e.value for e in LogFormat],
        default=LogFormat.JSON.value,
        help="Logging format: json (default) or text.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    # When piping output to tools like `head`, avoid noisy BrokenPipeError on stdout.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    args = _build_parser().parse_args(argv)

    log_format = LogFormat(args.log_format)
    level = "DEBUG" if args.verbose else args.log_level
    setup_logging(level=level, log_format=log_format)

    input_path = args.input
    output_path = args.output
    rules_path = args.rules
    exclude_path = args.exclude

    if not input_path.exists():
        _die(f"Input path does not exist: {input_path}")
    if not rules_path.exists():
        _die(f"Rules file does not exist: {rules_path}")
    if exclude_path is not None and not exclude_path.exists():
        _die(f"Exclude file does not exist: {exclude_path}")

    # Normalize for reproducibility in logs.
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    rules_path = rules_path.resolve()
    exclude_path = exclude_path.resolve() if exclude_path is not None else None

    try:
        if args.dry_run:
            _dry_run(
                input_path=input_path,
                output_dir=output_path,
                rules_path=rules_path,
                exclude_path=exclude_path,
                exclude_case_insensitive=bool(args.exclude_case_insensitive),
                include_builtin=not bool(args.no_default_rules),
            )
            return

        cfg = ProcessorConfig(
            max_workers=8,
            exclude_case_insensitive=bool(args.exclude_case_insensitive),
            include_builtin_rules=not bool(args.no_default_rules),
        )
        out_zip = process(
            input_path=input_path,
            rules_path=rules_path,
            output_dir=output_path,
            exclude_path=exclude_path,
            config=cfg,
        )
        print(str(out_zip))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except BrokenPipeError:
        # Consumer closed the pipe (e.g., `head`); exit silently.
        try:
            sys.stdout.close()
        finally:
            raise SystemExit(141) from None
    except Exception as exc:  # noqa: BLE001 (CLI boundary)
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc


def _dry_run(
    *,
    input_path: Path,
    output_dir: Path,
    rules_path: Path,
    exclude_path: Path | None,
    exclude_case_insensitive: bool,
    include_builtin: bool,
) -> None:
    """
    Dry-run mode: validate inputs, load rules, apply excludes, and report what would be done.
    """
    if output_dir.exists() and not output_dir.is_dir():
        _die(f"--output must be a directory: {output_dir}")

    user_rules = load_rules(rules_path)
    rules = merge_rules(builtin=default_rules(), user=user_rules) if include_builtin else user_rules
    if not rules:
        _die("No valid rules loaded; nothing to do.")

    with handle_input(input_path) as prepared:
        base_dir = prepared.working_dir
        files = prepared.files
        exclude_filter = (
            ExcludeFilter.from_file(
                exclude_path, base_dir=base_dir, case_insensitive=exclude_case_insensitive
            )
            if exclude_path is not None
            else None
        )
        filtered = [f for f in files if not (exclude_filter and exclude_filter.should_exclude(f))]

    zip_path = output_dir.with_suffix(".zip")
    print("DRY RUN")
    print(f"- Input: {input_path}")
    print(f"- Output dir: {output_dir}")
    print(f"- Output zip: {zip_path}")
    print(f"- Rules: {len(rules)} (user={len(user_rules)}, builtin={'on' if include_builtin else 'off'})")
    print(f"- Files: total={len(files)}, excluded={len(files) - len(filtered)}, to_process={len(filtered)}")
    for p in filtered[:20]:
        print(f"  - {p}")
    if len(filtered) > 20:
        print(f"  ... ({len(filtered) - 20} more)")


def _die(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)
