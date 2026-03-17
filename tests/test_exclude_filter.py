from __future__ import annotations

from pathlib import Path

from log_anonymizer.exclude_filter import ExcludeFilter


def test_exclude_filter_matches_basename_and_relative(tmp_path: Path) -> None:
    base = tmp_path / "root"
    (base / "debug").mkdir(parents=True)
    f1 = base / "a.tmp"
    f2 = base / "debug" / "x.log"
    f1.write_text("x", encoding="utf-8")
    f2.write_text("y", encoding="utf-8")

    filt = ExcludeFilter.from_patterns(["*.tmp", "*/debug/*"], base_dir=base)
    assert filt.should_exclude(f1) is True
    assert filt.should_exclude(f2) is True


def test_exclude_filter_case_insensitive(tmp_path: Path) -> None:
    base = tmp_path / "root"
    (base / "Logs").mkdir(parents=True)
    f = base / "Logs" / "App.LOG"
    f.write_text("x", encoding="utf-8")

    filt = ExcludeFilter.from_patterns(["**/*.log"], base_dir=base, case_insensitive=True)
    assert filt.should_exclude(f) is True

