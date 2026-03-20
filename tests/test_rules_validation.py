from __future__ import annotations

import json

from log_anonymizer.rules_validation import validate_rules_json_bytes


def test_validate_rules_json_bytes_accepts_v1_legacy() -> None:
    payload = {
        "version": 1,
        "rules": [{"search": r"abc", "replace": "[X]", "trigger": "", "caseSensitive": "true"}],
    }
    err = validate_rules_json_bytes((json.dumps(payload) + "\n").encode("utf-8"))
    assert err is None


def test_validate_rules_json_bytes_accepts_v2_action() -> None:
    payload = {
        "version": 2,
        "rules": [
            {
                "search": r"\b\d{4}\b",
                "action": {"type": "mask", "maskChar": "*", "keepLast": 0},
            }
        ],
    }
    err = validate_rules_json_bytes((json.dumps(payload) + "\n").encode("utf-8"))
    assert err is None


def test_validate_rules_json_bytes_accepts_mixed_v2_and_legacy_rules() -> None:
    payload = {
        "version": 2,
        "rules": [
            {"search": r"abc", "replace": "[X]"},
            {"search": r"\b\d{4}\b", "action": {"type": "mask", "maskChar": "*", "keepLast": 2}},
        ],
    }
    err = validate_rules_json_bytes((json.dumps(payload) + "\n").encode("utf-8"))
    assert err is None


def test_validate_rules_json_bytes_rejects_invalid_action() -> None:
    payload = {
        "version": 2,
        "rules": [{"search": r"x+", "action": {"type": "nope"}}],
    }
    err = validate_rules_json_bytes(json.dumps(payload).encode("utf-8"))
    assert err is not None
    assert "action invalid" in err
