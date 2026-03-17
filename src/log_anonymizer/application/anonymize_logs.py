from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from pathlib import Path

from log_anonymizer.engine.anonymizer import AnonymizationEngine
from log_anonymizer.infrastructure.filtering.exclude_filter import ExcludeFilter
from log_anonymizer.infrastructure.filtering.file_collector import collect_files
from log_anonymizer.infrastructure.input_handlers.directory import DirectoryInputHandler
from log_anonymizer.infrastructure.input_handlers.single_file import SingleFileInputHandler
from log_anonymizer.infrastructure.input_handlers.zip_archive import ZipArchiveInputHandler
from log_anonymizer.infrastructure.output.zip_output import ZipOutputManager
from log_anonymizer.infrastructure.rules_loader.json_rules_loader import JsonRulesLoader
from log_anonymizer.utils.io import open_text_best_effort

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnonymizeLogsRequest:
    input_path: Path
    output_zip_path: Path
    rules_path: Path
    exclude_path: Path | None = None
    salt: str | None = None


def anonymize_logs(req: AnonymizeLogsRequest) -> None:
    input_path = req.input_path
    logger.info("starting", extra={"input": str(input_path), "output": str(req.output_zip_path)})

    ruleset = JsonRulesLoader(req.rules_path).load()
    salt = req.salt or secrets.token_hex(16)
    if req.salt is None:
        logger.info("generated_salt", extra={"salt": salt})

    engine = AnonymizationEngine(rules=ruleset.rules, hash_config=ruleset.hash_config, salt=salt)

    handler = _select_input_handler(input_path)
    prepared = handler.prepare(input_path)
    try:
        exclude = _load_exclude(req.exclude_path, prepared.root_dir, input_path)
        files = collect_files(root_dir=prepared.root_dir, only_relative=prepared.only_relative, exclude=exclude)
        logger.info("collected_files", extra={"count": len(files)})

        with ZipOutputManager(req.output_zip_path) as out:
            for f in files:
                _anonymize_one(engine, f.absolute_path, out.root_dir / f.relative_path)
        logger.info("done", extra={"output": str(req.output_zip_path), "files": len(files)})
    finally:
        prepared.cleanup()


def _select_input_handler(input_path: Path):
    if input_path.is_dir():
        return DirectoryInputHandler()
    if input_path.is_file() and input_path.suffix.lower() == ".zip":
        return ZipArchiveInputHandler()
    if input_path.is_file():
        return SingleFileInputHandler()
    raise ValueError(f"Unsupported input path: {input_path}")


def _load_exclude(exclude_path: Path | None, prepared_root: Path, original_input: Path) -> ExcludeFilter | None:
    if exclude_path is not None:
        return ExcludeFilter.from_file(exclude_path)

    # If user didn't provide one, auto-detect `.exclude` next to the original input (dir/file)
    # or at the root of the extracted archive.
    candidates: list[Path] = []
    if original_input.is_dir():
        candidates.append(original_input / ".exclude")
    elif original_input.is_file():
        candidates.append(original_input.parent / ".exclude")
    candidates.append(prepared_root / ".exclude")

    for c in candidates:
        if c.exists() and c.is_file():
            logger.info("using_exclude_file", extra={"path": str(c)})
            return ExcludeFilter.from_file(c)
    return None


def _anonymize_one(engine: AnonymizationEngine, src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    logger.info("anonymizing_file", extra={"src": str(src), "dest": str(dest)})

    try:
        with open_text_best_effort(src) as fin, dest.open("w", encoding="utf-8", newline="") as fout:
            for line in fin:
                fout.write(engine.anonymize_text(line))
    except ValueError as exc:
        logger.warning("skipping_file", extra={"src": str(src), "reason": str(exc)})
