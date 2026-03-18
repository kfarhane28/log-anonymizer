from __future__ import annotations

from pathlib import Path

import pytest

from log_anonymizer.application.preview_anonymization import (
    PreviewAnonymizationRequest,
    preview_anonymization,
)


def test_preview_uses_builtin_rules_by_default() -> None:
    res = preview_anonymization(
        PreviewAnonymizationRequest(
            text="user=bob password=secret principal hdfs/nn1.example.com@EXAMPLE.COM\n",
            rules_path=None,
            include_builtin_rules=True,
        )
    )
    assert "user=[USER]" in res.anonymized_text
    assert "password=[REDACTED]" in res.anonymized_text
    assert "[KRB_PRINCIPAL]" in res.anonymized_text
    assert res.lines_in == 1
    assert res.lines_out == 1
    assert res.stats.total_replacements >= 1


def test_preview_applies_user_rules_when_provided(tmp_path: Path) -> None:
    rules_path = tmp_path / "rules.json"
    rules_path.write_text(
        """
        {
          "version": 1,
          "rules": [
            {
              "description": "secret",
              "trigger": "SECRET=",
              "search": "SECRET=[^ ]+",
              "replace": "SECRET=[REDACTED]",
              "caseSensitive": "true"
            }
          ]
        }
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    res = preview_anonymization(
        PreviewAnonymizationRequest(
            text="ok SECRET=abc other\n",
            rules_path=rules_path,
            include_builtin_rules=False,
        )
    )
    assert res.anonymized_text == "ok SECRET=[REDACTED] other\n"
    assert res.rules_count == 1


def test_preview_requires_rules_if_builtin_disabled() -> None:
    with pytest.raises(ValueError):
        preview_anonymization(
            PreviewAnonymizationRequest(text="hello\n", rules_path=None, include_builtin_rules=False)
        )


def test_builtin_ipv6_rule_does_not_match_timestamps() -> None:
    text = "[09/Mar/2026 12:50:34 +0100] access\n"
    res = preview_anonymization(PreviewAnonymizationRequest(text=text, rules_path=None, include_builtin_rules=True))
    assert "12:50:34" in res.anonymized_text
    assert "[IPV6]" not in res.anonymized_text


def test_builtin_rules_do_not_turn_file_extensions_into_hostnames() -> None:
    text = 'GET /webhdfs/v1/user/bob/file.txt?op=OPEN HTTP/1.1"\n'
    res = preview_anonymization(
        PreviewAnonymizationRequest(text=text, rules_path=None, include_builtin_rules=True)
    )
    assert "file.txt" in res.anonymized_text
    assert "[HOST]" not in res.anonymized_text
