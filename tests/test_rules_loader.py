from __future__ import annotations

import json
from pathlib import Path

import pytest

from log_anonymizer.rules_loader import Rule, load_rules


def test_load_rules_valid_and_invalid_regex(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    rules_json = {
        "version": 1,
        "rules": [
            {
                "description": "valid",
                "trigger": "user=",
                "search": r"\buser=([A-Za-z0-9._-]+)\b",
                "replace": "user=[USER]",
                "caseSensitive": "false",
            },
            {
                "description": "invalid_regex",
                "trigger": "x",
                "search": r"(",
                "replace": "y",
                "caseSensitive": "true",
            },
            {
                "description": "no_trigger",
                "search": r"abc",
                "replace": "x",
            },
            {
                "description": "missing_replace",
                "trigger": "x",
                "search": r"x+",
            },
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")

    caplog.set_level("WARNING")
    rules = load_rules(p)

    assert len(rules) == 2
    assert isinstance(rules[0], Rule)
    assert rules[0].description == "valid"
    assert rules[0].case_sensitive is False
    assert rules[1].description == "no_trigger"
    assert rules[1].trigger == ""

    # Ensure warnings for invalid rules were emitted.
    messages = [r.message for r in caplog.records]
    assert "invalid_rule_skipped" in messages


def test_load_rules_rejects_wrong_version(tmp_path: Path) -> None:
    p = tmp_path / "rules.json"
    p.write_text(json.dumps({"version": 2, "rules": []}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_rules(p)
