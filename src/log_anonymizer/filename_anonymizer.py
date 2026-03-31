from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from log_anonymizer.anonymizer import anonymize_text_block
from log_anonymizer.rules_loader import Rule
from log_anonymizer.rule_actions import ActionContext

logger = logging.getLogger(__name__)


_INVALID_CHARS_RE = re.compile(r'[<>:"/\\\\|?*\x00-\x1F]')


@dataclass(frozen=True)
class FilenameAnonymizationStats:
    paths_total: int
    paths_changed: int
    components_changed: int
    collisions_resolved: int


class FilenameAnonymizer:
    """
    Anonymize output file/folder names (not input) using the existing rules engine.

    Strategy:
    - Apply anonymization rules to each path *component* (folder names + file stem).
    - Preserve file extensions (all suffixes, e.g. ".tar.gz") where possible.
    - Sanitize invalid filesystem characters to "_" and avoid empty names.
    - Resolve collisions deterministically within each output directory by appending
      a stable hash-based suffix to the stem.
    """

    def __init__(self, *, rules: Iterable[Rule], action_context: ActionContext | None = None) -> None:
        self._rules = list(rules)
        self._ctx = action_context or ActionContext()

    def build_relpath_map(self, rel_paths: Iterable[Path]) -> tuple[dict[Path, Path], FilenameAnonymizationStats]:
        """
        Build a deterministic mapping from original relative paths to anonymized output paths.
        """
        rel_list = [Path(p.as_posix()) for p in rel_paths]
        rel_list.sort(key=lambda p: p.as_posix())

        used_children: dict[tuple[str, ...], set[str]] = {}
        dir_map: dict[tuple[str, ...], tuple[str, ...]] = {}
        out_map: dict[Path, Path] = {}

        paths_changed = 0
        components_changed = 0
        collisions_resolved = 0

        for rel in rel_list:
            parts = tuple(rel.parts)
            if not parts:
                continue

            orig_parent: tuple[str, ...] = ()
            anon_parent: tuple[str, ...] = ()

            # Resolve / memoize directories first so nested paths stay consistent.
            for idx, comp in enumerate(parts[:-1]):
                orig_dir = orig_parent + (comp,)
                if orig_dir in dir_map:
                    anon_parent = dir_map[orig_dir]
                    orig_parent = orig_dir
                    continue

                anon_name, changed = self._anonymize_dir_component(comp)
                if changed:
                    components_changed += 1

                used = used_children.setdefault(anon_parent, set())
                unique, did_collide = _make_unique_component(
                    anon_name, used=used, suffix_source="/".join(orig_dir)
                )
                used.add(unique)
                if did_collide:
                    collisions_resolved += 1

                anon_parent = anon_parent + (unique,)
                dir_map[orig_dir] = anon_parent
                orig_parent = orig_dir

            # File component (preserve extension).
            file_name = parts[-1]
            anon_file, changed_file = self._anonymize_file_component(file_name)
            if changed_file:
                components_changed += 1

            used = used_children.setdefault(anon_parent, set())
            unique_file, did_collide = _make_unique_component(
                anon_file, used=used, suffix_source=rel.as_posix()
            )
            used.add(unique_file)
            if did_collide:
                collisions_resolved += 1

            anon_rel = Path(*anon_parent, unique_file)
            out_map[rel] = anon_rel
            if anon_rel.as_posix() != rel.as_posix():
                paths_changed += 1

        stats = FilenameAnonymizationStats(
            paths_total=len(rel_list),
            paths_changed=paths_changed,
            components_changed=components_changed,
            collisions_resolved=collisions_resolved,
        )
        return out_map, stats

    def _anonymize_dir_component(self, name: str) -> tuple[str, bool]:
        anonymized, changed = self._apply_rules(name)
        sanitized = _sanitize_component(anonymized)
        return sanitized, changed or (sanitized != name)

    def _anonymize_file_component(self, name: str) -> tuple[str, bool]:
        stem, ext = _split_all_suffixes(name)
        if stem:
            new_stem, changed = self._apply_rules(stem)
        else:
            new_stem, changed = stem, False
        new_stem = _sanitize_component(new_stem) if new_stem else "_"
        # Keep extension shape; still sanitize to avoid invalid bytes/controls.
        ext_s = _sanitize_extension(ext)
        out = new_stem + ext_s
        return out, changed or (out != name)

    def _apply_rules(self, s: str) -> tuple[str, bool]:
        if not s or not self._rules:
            return s, False
        out, stats = anonymize_text_block(s, self._rules, action_context=self._ctx)
        out = out.replace("\n", "").replace("\r", "")
        return out, stats.total_replacements > 0


def _split_all_suffixes(name: str) -> tuple[str, str]:
    """
    Split a filename into (stem, ext) where ext is all suffixes joined (e.g. ".tar.gz").
    """
    p = Path(name)
    suffixes = p.suffixes
    if not suffixes:
        return name, ""
    ext = "".join(suffixes)
    stem = name[: -len(ext)] if len(ext) < len(name) else ""
    return stem, ext


def _sanitize_extension(ext: str) -> str:
    if not ext:
        return ""
    # Extensions are expected to be dot-prefixed and mostly ASCII, but still sanitize controls.
    cleaned = _INVALID_CHARS_RE.sub("_", ext)
    # Avoid trailing dots/spaces for Windows compatibility.
    cleaned = cleaned.rstrip(" .")
    # Keep at least the leading dot if any.
    if cleaned and not cleaned.startswith("."):
        cleaned = "." + cleaned.lstrip(".")
    return cleaned


def _sanitize_component(name: str) -> str:
    s = (name or "").strip()
    s = s.replace("\x00", "")
    s = _INVALID_CHARS_RE.sub("_", s)
    # Avoid Windows-invalid trailing spaces/dots.
    s = s.rstrip(" .")
    if not s:
        return "_"
    # Keep components reasonably bounded to common filesystem limits.
    if len(s) > 200:
        h = hashlib.sha1(s.encode("utf-8", errors="replace")).hexdigest()[:10]
        s = s[:180].rstrip(" .") + "__" + h
    return s


def _make_unique_component(name: str, *, used: set[str], suffix_source: str) -> tuple[str, bool]:
    """
    Ensure a unique component name inside a directory.
    """
    if name not in used:
        return name, False

    stem, ext = _split_all_suffixes(name)
    h = hashlib.sha1(suffix_source.encode("utf-8", errors="replace")).hexdigest()[:8]
    base = _sanitize_component(stem) if stem else "_"
    candidate = f"{base}__{h}{ext}"
    if candidate not in used:
        return candidate, True

    # Extremely unlikely, but keep deterministic by adding a counter.
    i = 2
    while True:
        c = f"{base}__{h}__{i}{ext}"
        if c not in used:
            return c, True
        i += 1
