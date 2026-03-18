from __future__ import annotations

from pathlib import Path

from log_anonymizer.exclude_filter import ExcludeFilter, default_patterns


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


def test_exclude_filter_negation_last_match_wins(tmp_path: Path) -> None:
    base = tmp_path / "root"
    (base / "dir").mkdir(parents=True)
    f = base / "dir" / "important-stacktrace.log"
    f.write_text("x", encoding="utf-8")

    filt = ExcludeFilter.from_patterns(["**/*.log", "!**/important-stacktrace.log"], base_dir=base)
    assert filt.should_exclude(f) is False


def test_default_exclude_patterns_include_key_material(tmp_path: Path) -> None:
    base = tmp_path / "root"
    base.mkdir()
    f = base / "krb5.conf"
    f.write_text("x", encoding="utf-8")

    filt = ExcludeFilter.from_patterns(default_patterns(), base_dir=base)
    assert filt.should_exclude(f) is True
