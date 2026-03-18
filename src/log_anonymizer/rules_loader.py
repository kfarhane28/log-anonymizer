from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rule:
    """
    A single anonymization rule.

    Attributes:
        description: Human-readable description (may be empty).
        trigger: Substring used as a fast pre-check before running the regex.
        regex: Compiled regex used for the replacement.
        replacement: Replacement string passed to `re.sub`.
        case_sensitive: Whether trigger check and regex are case sensitive.
    """

    description: str
    trigger: str
    regex: re.Pattern[str]
    replacement: str
    case_sensitive: bool

    def triggered_by(self, line: str) -> bool:
        if self.case_sensitive:
            return self.trigger in line
        return self.trigger.lower() in line.lower()


def load_rules(rules_path: Path) -> list[Rule]:
    """
    Load and validate rules from a JSON file.

    Expected format:
    {
      "version": 1,
      "rules": [
        {
          "description": "...",
          "trigger": "...",
          "search": "...",
          "replace": "...",
          "caseSensitive": "false"
        }
      ]
    }

    Behavior:
    - Validates presence of required fields.
    - Normalizes `caseSensitive` to a boolean (default: true).
    - Compiles regex patterns; invalid rules are skipped with a warning.
    """
    data = _load_json(rules_path)
    version = data.get("version")
    if version != 1:
        raise ValueError(f"Unsupported rules version: {version!r} (expected 1)")

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("'rules' must be a list")

    out: list[Rule] = []
    for idx, raw in enumerate(raw_rules):
        rule = _parse_rule(raw, index=idx, rules_path=rules_path)
        if rule is not None:
            out.append(rule)

    # An empty rules file is valid (e.g., when relying on built-in rules only).
    logger.info("rules_loaded", extra={"path": str(rules_path), "count": len(out)})
    return out


def _load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError("rules.json must contain a JSON object")
    return data


def _parse_rule(raw: Any, *, index: int, rules_path: Path) -> Rule | None:
    if not isinstance(raw, dict):
        logger.warning("invalid_rule_skipped", extra={"index": index, "reason": "not_an_object"})
        return None

    description = str(raw.get("description") or "")

    trigger = raw.get("trigger")
    if not isinstance(trigger, str) or not trigger:
        logger.warning(
            "invalid_rule_skipped",
            extra={"index": index, "reason": "missing_trigger", "description": description},
        )
        return None

    search = raw.get("search")
    if not isinstance(search, str) or not search:
        logger.warning(
            "invalid_rule_skipped",
            extra={"index": index, "reason": "missing_search", "description": description},
        )
        return None

    replace = raw.get("replace")
    if replace is None:
        replacement = ""
    elif isinstance(replace, str):
        replacement = replace
    else:
        logger.warning(
            "invalid_rule_skipped",
            extra={"index": index, "reason": "replace_not_string", "description": description},
        )
        return None

    case_sensitive = _normalize_case_sensitive(raw.get("caseSensitive"), default=True)
    flags = 0 if case_sensitive else re.IGNORECASE

    try:
        regex = re.compile(search, flags=flags)
    except re.error as exc:
        logger.warning(
            "invalid_rule_skipped",
            extra={
                "index": index,
                "reason": "invalid_regex",
                "error": str(exc),
                "search": search,
                "path": str(rules_path),
                "description": description,
            },
        )
        return None

    return Rule(
        description=description,
        trigger=trigger,
        regex=regex,
        replacement=replacement,
        case_sensitive=case_sensitive,
    )


def _normalize_case_sensitive(value: Any, *, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "1", "yes", "y"):
            return True
        if v in ("false", "0", "no", "n"):
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    logger.warning("invalid_caseSensitive_value", extra={"value": str(value)})
    return default
