from __future__ import annotations

import json
from pathlib import Path

import pytest

from log_anonymizer.anonymizer import anonymize_text_block
from log_anonymizer.rule_actions import ActionContext
from log_anonymizer.rules_loader import load_rules


def test_legacy_fixed_replace_still_works(tmp_path: Path) -> None:
    rules_json = {
        "version": 1,
        "rules": [
            {
                "description": "UUID",
                "trigger": "-",
                "search": r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
                "replace": "[UUID]",
                "caseSensitive": "true",
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    out, stats = anonymize_text_block(
        "id=123e4567-e89b-12d3-a456-426614174000\n",
        rules,
    )
    assert out == "id=[UUID]\n"
    assert stats.total_replacements == 1


def test_redaction_action(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Redact secret",
                "trigger": "secret=",
                "search": r"secret=[^\s]+",
                "action": {"type": "redaction"},
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    out, stats = anonymize_text_block("x secret=abc y\n", rules)
    assert out == "x  y\n"
    assert stats.total_replacements == 1


def test_mask_full(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Mask digits",
                "trigger": "",
                "search": r"\b\d{4}\b",
                "action": {"type": "mask", "maskChar": "*"},
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    out, _ = anonymize_text_block("pin=1234\n", rules)
    assert out == "pin=****\n"


def test_mask_keep_last_n(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Mask account",
                "trigger": "acct=",
                "search": r"\b\d{16}\b",
                "action": {"type": "mask", "maskChar": "*", "keepLast": 4},
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    out, _ = anonymize_text_block("acct=1234567890123456\n", rules)
    assert out == "acct=************3456\n"


def test_secure_hash_deterministic_with_context_salt(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Hash email",
                "trigger": "@",
                "search": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                "action": {"type": "secure_hash", "algorithm": "sha256", "length": 16},
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    ctx_a = ActionContext(salt="salt-a")
    out1, _ = anonymize_text_block("mail=a@example.com\n", rules, action_context=ctx_a)
    out2, _ = anonymize_text_block("mail=a@example.com\n", rules, action_context=ctx_a)
    assert out1 == out2

    ctx_b = ActionContext(salt="salt-b")
    out3, _ = anonymize_text_block("mail=a@example.com\n", rules, action_context=ctx_b)
    assert out3 != out1


def test_bucket_mapping_group_replacement(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Bucket age",
                "trigger": "age=",
                "search": r"\bage=(\d+)\b",
                "action": {
                    "type": "bucket",
                    "group": 1,
                    "fallbackLabel": "other",
                    "buckets": [
                        {"min": 0, "max": 17, "label": "0-17"},
                        {"min": 18, "max": 29, "label": "18-29"},
                        {"min": 30, "max": 49, "label": "30-49"},
                        {"min": 50, "max": 200, "label": "50+"},
                    ],
                },
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    rules = load_rules(p, strict=True)

    out, _ = anonymize_text_block("age=23 age=5 age=999\n", rules)
    assert out == "age=18-29 age=0-17 age=other\n"


def test_invalid_action_config_rejected_in_strict_mode(tmp_path: Path) -> None:
    rules_json = {
        "version": 2,
        "rules": [
            {
                "description": "Bad",
                "trigger": "",
                "search": "x+",
                "action": {"type": "does_not_exist"},
            }
        ],
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(rules_json), encoding="utf-8")
    with pytest.raises(ValueError, match=r"Unknown action\.type"):
        load_rules(p, strict=True)
