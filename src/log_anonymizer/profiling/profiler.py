from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from log_anonymizer.profiling.detectors import Detection, SensitivePatternDetector, default_detectors
from log_anonymizer.profiling.suggestions import suggested_rules_json
from log_anonymizer.utils.io import open_text_best_effort

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProfilingConfig:
    detectors: tuple[str, ...] = ("email", "ipv4", "token", "card")
    max_examples_per_kind: int = 5


@dataclass
class ProfilingReport:
    version: int
    generated_at: str
    detectors: tuple[str, ...]
    files_scanned: int
    matches_by_kind: dict[str, int]
    files_by_kind: dict[str, dict[str, int]]
    masked_examples_by_kind: dict[str, list[str]]
    suggested_rules: dict[str, Any]

    def to_json_obj(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "detectors": list(self.detectors),
            "files_scanned": self.files_scanned,
            "matches_by_kind": dict(sorted(self.matches_by_kind.items(), key=lambda kv: kv[0])),
            "files_by_kind": {
                k: dict(sorted(v.items(), key=lambda kv: kv[0]))
                for k, v in sorted(self.files_by_kind.items(), key=lambda kv: kv[0])
            },
            "masked_examples_by_kind": dict(
                sorted(self.masked_examples_by_kind.items(), key=lambda kv: kv[0])
            ),
            "suggested_rules": self.suggested_rules,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_json_obj(), ensure_ascii=False, indent=2) + "\n"


class SensitiveDataProfiler:
    def __init__(self, *, config: ProfilingConfig | None = None) -> None:
        self._config = config or ProfilingConfig()
        self._registry = default_detectors()

    def _selected_detectors(self) -> list[SensitivePatternDetector]:
        detectors: list[SensitivePatternDetector] = []
        for name in self._config.detectors:
            d = self._registry.get(name)
            if d is None:
                raise ValueError(f"Unknown detector: {name}")
            detectors.append(d)
        return detectors

    def profile_text(self, text: str, *, source_name: str = "<text>") -> ProfilingReport:
        lines = text.splitlines()
        return self._profile_iter(lines, source_name=source_name)

    def profile_files(self, files: list[Path], *, base_dir: Path | None = None) -> ProfilingReport:
        detectors = self._selected_detectors()
        counts: dict[str, int] = {}
        files_by_kind: dict[str, dict[str, int]] = {}
        examples: dict[str, list[str]] = {}

        scanned = 0
        for path in files:
            scanned += 1
            rel = _safe_rel(path, base_dir)
            try:
                with open_text_best_effort(path) as fin:
                    for line in fin:
                        for det in detectors:
                            for detection in det.detect(line):
                                _accumulate(
                                    detection,
                                    file_key=rel,
                                    counts=counts,
                                    files_by_kind=files_by_kind,
                                    examples=examples,
                                    max_examples=self._config.max_examples_per_kind,
                                )
            except ValueError:
                # Should already be filtered out by the file collection, but keep this defensive.
                logger.info("Skipping non-text file: %s", path)
                continue

        detected_kinds = set(counts.keys())
        report = ProfilingReport(
            version=1,
            generated_at=_now_iso(),
            detectors=tuple(self._config.detectors),
            files_scanned=scanned,
            matches_by_kind=counts,
            files_by_kind=files_by_kind,
            masked_examples_by_kind=examples,
            suggested_rules=suggested_rules_json(detected_kinds),
        )
        return report

    def _profile_iter(self, lines: list[str], *, source_name: str) -> ProfilingReport:
        detectors = self._selected_detectors()
        counts: dict[str, int] = {}
        files_by_kind: dict[str, dict[str, int]] = {}
        examples: dict[str, list[str]] = {}

        for line in lines:
            for det in detectors:
                for detection in det.detect(line):
                    _accumulate(
                        detection,
                        file_key=source_name,
                        counts=counts,
                        files_by_kind=files_by_kind,
                        examples=examples,
                        max_examples=self._config.max_examples_per_kind,
                    )

        detected_kinds = set(counts.keys())
        return ProfilingReport(
            version=1,
            generated_at=_now_iso(),
            detectors=tuple(self._config.detectors),
            files_scanned=1,
            matches_by_kind=counts,
            files_by_kind=files_by_kind,
            masked_examples_by_kind=examples,
            suggested_rules=suggested_rules_json(detected_kinds),
        )


def _accumulate(
    detection: Detection,
    *,
    file_key: str,
    counts: dict[str, int],
    files_by_kind: dict[str, dict[str, int]],
    examples: dict[str, list[str]],
    max_examples: int,
) -> None:
    kind = detection.kind
    counts[kind] = counts.get(kind, 0) + 1
    files_by_kind.setdefault(kind, {})
    files_by_kind[kind][file_key] = files_by_kind[kind].get(file_key, 0) + 1
    if max_examples <= 0:
        return
    examples.setdefault(kind, [])
    if len(examples[kind]) < max_examples and detection.masked_example not in examples[kind]:
        examples[kind].append(detection.masked_example)


def _safe_rel(path: Path, base_dir: Path | None) -> str:
    try:
        if base_dir is None:
            return str(path)
        return path.resolve().relative_to(base_dir.resolve()).as_posix()
    except Exception:
        return str(path)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

