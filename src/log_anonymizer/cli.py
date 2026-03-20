from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path
from queue import Queue
from typing import NoReturn

from log_anonymizer.builtin_rules import default_rules, merge_rules
from log_anonymizer.config.app_config import load_config, resolve_config_path
from log_anonymizer.config.logging_config import LogFormat, setup_logging
from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns, load_patterns
from log_anonymizer.input_handler import handle_input
from log_anonymizer.profiling.runner import run_sensitive_data_profiling
from log_anonymizer.processor import ProcessorConfig, process
from log_anonymizer.progress import ProgressEvent, ProgressStopToken, QueueProgressReporter
from log_anonymizer.progress_cli import start_cli_progress_thread
from log_anonymizer.rules_loader import load_rules


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-anonymizer",
        description="Anonymize Hadoop/Cloudera logs (directory, file, or archive). Writes a single .tar.gz archive into the output directory.",
    )
    parser.add_argument(
        "--input",
        "-i",
        type=Path,
        required=True,
        help="Input path (directory, single file, or .zip/.tar.gz archive).",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        required=True,
        help="Output directory where a single .tar.gz archive will be written.",
    )
    parser.add_argument(
        "--rules",
        "-r",
        type=Path,
        default=None,
        help="Optional rules JSON file. If omitted, the built-in rules are used (unless --no-default-rules).",
    )
    parser.add_argument(
        "--exclude",
        "-x",
        type=Path,
        default=None,
        help="Optional .exclude file with glob patterns (appended after built-in excludes; use '!pattern' to re-include).",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Optional config file (INI). Default: ./log-anonymizer.ini or $LOG_ANONYMIZER_CONFIG",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate and report what would be processed without writing output.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable DEBUG logging.")
    parser.add_argument("--exclude-case-insensitive", action="store_true", help="Case-insensitive exclude matching.")
    parser.add_argument("--no-default-rules", action="store_true", help="Do not include built-in Hadoop-sensitive rules.")
    parser.add_argument(
        "--profile-sensitive-data",
        action="store_true",
        help="Enable optional sensitive-data profiling (heuristic) and rule suggestions.",
    )
    parser.add_argument(
        "--profiling-detectors",
        default="email,ipv4,token,card",
        help="Comma-separated detectors to run in profiling mode (default: email,ipv4,token,card).",
    )
    parser.add_argument(
        "--profiling-report",
        type=Path,
        default=None,
        help="Optional path to write profiling report JSON (default: <output>/profiling_report.json).",
    )
    parser.add_argument(
        "--suggest-rules-output",
        type=Path,
        default=None,
        help="Optional path to write suggested rules JSON (default: <output>/suggested_rules.json).",
    )
    parser.add_argument(
        "--log-level",
        default=None,
        help="Logging level (overrides config; default: INFO).",
    )
    parser.add_argument(
        "--log-format",
        choices=[e.value for e in LogFormat],
        default=None,
        help="Logging format: json or text (overrides config; default: json).",
    )
    parser.add_argument(
        "--parallel",
        action="store_true",
        help="Enable parallel processing of files (default: disabled, sequential).",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=5,
        help="Max parallel workers when --parallel is enabled (default: 5).",
    )
    pg = parser.add_mutually_exclusive_group()
    pg.add_argument(
        "--progress",
        action="store_true",
        help="Force progress display (writes to stderr).",
    )
    pg.add_argument(
        "--no-progress",
        action="store_true",
        help="Disable progress display (useful when redirecting stderr).",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    # When piping output to tools like `head`, avoid noisy BrokenPipeError on stdout.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    args = _build_parser().parse_args(argv)

    cfg_path = resolve_config_path(args.config)
    cfg = load_config(cfg_path)

    fmt_str = args.log_format or cfg.logging.fmt or LogFormat.JSON.value
    log_format = LogFormat(fmt_str)
    if args.verbose:
        level = "DEBUG"
    else:
        level = args.log_level or cfg.logging.level or "INFO"
    setup_logging(level=level, log_format=log_format)

    input_path = args.input
    output_path = args.output
    rules_path = args.rules
    exclude_path = args.exclude

    if not input_path.exists():
        _die(f"Input path does not exist: {input_path}")
    if rules_path is not None and not rules_path.exists():
        _die(f"Rules file does not exist: {rules_path}")
    if exclude_path is not None and not exclude_path.exists():
        _die(f"Exclude file does not exist: {exclude_path}")
    if args.no_default_rules and rules_path is None:
        _die("--no-default-rules requires providing --rules (otherwise there are no rules to apply).")
    if args.max_workers is not None and args.max_workers <= 0:
        _die(f"--max-workers must be >= 1 (got {args.max_workers})")

    # Normalize for reproducibility in logs.
    input_path = input_path.resolve()
    output_path = output_path.resolve()
    rules_path = rules_path.resolve() if rules_path is not None else None
    exclude_path = exclude_path.resolve() if exclude_path is not None else None

    try:
        if args.dry_run:
            detectors = tuple(
                p.strip()
                for p in str(args.profiling_detectors or "").split(",")
                if p.strip()
            ) or ("email", "ipv4", "token", "card")
            if args.profile_sensitive_data:
                res = run_sensitive_data_profiling(
                    input_path=input_path,
                    output_dir=output_path,
                    exclude_path=exclude_path,
                    exclude_case_insensitive=bool(args.exclude_case_insensitive),
                    detectors=detectors,
                    profiling_report_path=args.profiling_report,
                    suggest_rules_output_path=args.suggest_rules_output,
                )
                print("DRY RUN (profiling only)")
                print(f"- Input: {input_path}")
                print(f"- Output dir: {output_path}")
                print(f"- Profiling report: {res.profiling_report_path}")
                print(f"- Suggested rules: {res.suggested_rules_path}")
                print(
                    f"- Files: total={res.total_files}, excluded={res.excluded_files}, profiled={res.profiled_files}"
                )
                return
            _dry_run(
                input_path=input_path,
                output_dir=output_path,
                rules_path=rules_path,
                exclude_path=exclude_path,
                exclude_case_insensitive=bool(args.exclude_case_insensitive),
                include_builtin=not bool(args.no_default_rules),
            )
            return

        detectors = tuple(
            p.strip()
            for p in str(args.profiling_detectors or "").split(",")
            if p.strip()
        ) or ("email", "ipv4", "token", "card")
        cfg = ProcessorConfig(
            parallel_enabled=bool(args.parallel),
            max_workers=int(args.max_workers or 5),
            exclude_case_insensitive=bool(args.exclude_case_insensitive),
            include_builtin_rules=not bool(args.no_default_rules),
            profile_sensitive_data=bool(args.profile_sensitive_data),
            profiling_detectors=detectors,
            profiling_report_path=args.profiling_report.resolve()
            if args.profiling_report is not None
            else None,
            suggest_rules_output_path=args.suggest_rules_output.resolve()
            if args.suggest_rules_output is not None
            else None,
            anonymization_salt=cfg.anonymization.salt,
        )
        enable_progress = bool(args.progress) or (
            not bool(args.no_progress) and sys.stderr.isatty()
        )
        q: Queue[ProgressEvent] | None = None
        stop: ProgressStopToken | None = None
        t = None
        reporter = None
        if enable_progress:
            q = Queue(maxsize=5000)
            stop = ProgressStopToken()
            reporter = QueueProgressReporter(q)
            t = start_cli_progress_thread(q, stop)
        try:
            out_zip = process(
                input_path=input_path,
                rules_path=rules_path,
                output_dir=output_path,
                exclude_path=exclude_path,
                config=cfg,
                progress=reporter,
            )
        finally:
            if stop is not None:
                stop.stop()
            if t is not None:
                t.join(timeout=2.0)
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
    rules_path: Path | None,
    exclude_path: Path | None,
    exclude_case_insensitive: bool,
    include_builtin: bool,
) -> None:
    """
    Dry-run mode: validate inputs, load rules, apply excludes, and report what would be done.
    """
    if output_dir.exists() and not output_dir.is_dir():
        _die(f"--output must be a directory: {output_dir}")

    user_rules = load_rules(rules_path) if rules_path is not None else []
    rules = merge_rules(builtin=default_rules(), user=user_rules) if include_builtin else user_rules
    if not rules:
        _die("No valid rules loaded; nothing to do.")

    with handle_input(input_path) as prepared:
        base_dir = prepared.working_dir
        files = prepared.files
        patterns = list(default_patterns())
        if exclude_path is not None:
            patterns.extend(load_patterns(exclude_path))
        exclude_filter = (
            ExcludeFilter.from_patterns(
                patterns, base_dir=base_dir, case_insensitive=exclude_case_insensitive
            )
            if patterns
            else None
        )
        filtered = [f for f in files if not (exclude_filter and exclude_filter.should_exclude(f))]

    zip_path = _default_output_archive_path(output_dir, input_path)
    print("DRY RUN")
    print(f"- Input: {input_path}")
    print(f"- Output dir: {output_dir}")
    print(f"- Output archive: {zip_path}")
    print(f"- Rules: {len(rules)} (user={len(user_rules)}, builtin={'on' if include_builtin else 'off'})")
    print(f"- Files: total={len(files)}, excluded={len(files) - len(filtered)}, to_process={len(filtered)}")
    for p in filtered[:20]:
        print(f"  - {p}")
    if len(filtered) > 20:
        print(f"  ... ({len(filtered) - 20} more)")


def _die(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


def _default_output_archive_path(output_dir: Path, input_path: Path) -> Path:
    out_dir = output_dir.resolve()
    name = input_path.name
    lower = name.lower()
    if lower.endswith(".tar.gz"):
        base = name[: -len(".tar.gz")]
    elif lower.endswith(".tgz"):
        base = name[: -len(".tgz")]
    elif lower.endswith(".zip"):
        base = input_path.stem
    else:
        base = input_path.stem or name
    return out_dir / f"{base}.tar.gz"
