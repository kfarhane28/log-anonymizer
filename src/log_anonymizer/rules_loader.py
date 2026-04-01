from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from log_anonymizer.rule_actions import ReplacementAction, RuleAction, parse_action

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Rule:
    """
    A single anonymization rule.

    Attributes:
        description: Human-readable description (may be empty).
        trigger: Optional substring used as a fast pre-check before running the regex.
        regex: Compiled regex used for the replacement.
        replacement: Replacement string passed to `re.sub`.
        case_sensitive: Whether trigger check and regex are case sensitive.
        action: Optional action strategy controlling how replacements are produced.
        enabled: Whether the rule is active (default: true). Disabled rules are ignored.
    """

    description: str
    trigger: str
    regex: re.Pattern[str]
    replacement: str
    case_sensitive: bool
    action: RuleAction | None = None
    enabled: bool = True

    def __post_init__(self) -> None:
        # Preserve backward compatibility for code/tests constructing Rule(...) directly.
        # If no action is provided, treat `replacement` as a fixed replacement operation.
        if self.action is None:
            object.__setattr__(self, "action", ReplacementAction(value=self.replacement))
        elif isinstance(self.action, ReplacementAction) and self.replacement != self.action.value:
            # Keep `replacement` in sync for callers that still read it.
            object.__setattr__(self, "replacement", self.action.value)

    def triggered_by(self, line: str) -> bool:
        if not self.enabled:
            return False
        if not self.trigger:
            return True
        if self.case_sensitive:
            return self.trigger in line
        return self.trigger.lower() in line.lower()


def load_rules(rules_path: Path, *, strict: bool = False) -> list[Rule]:
    """
    Load and validate rules from a JSON file.

    Expected format:
    {
      "version": 1,   # or 2
      "rules": [
        {
          "description": "...",
          "trigger": "...",
          "search": "...",
          "enable": true,               # optional; when omitted defaults to true
          "replace": "...",              # legacy fixed replacement
          "action": {"type": "...", ...} # new action-based format
          "caseSensitive": "false"
        }
      ]
    }

    Behavior:
    - Validates presence of required fields.
    - Normalizes `caseSensitive` to a boolean (default: true).
    - Compiles regex patterns; invalid rules are skipped with a warning.
    - When `strict=True`, invalid rules raise ValueError with explicit context.
    """
    data = _load_json(rules_path)
    version_raw = data.get("version", 1)
    try:
        version = int(version_raw)
    except Exception as exc:
        raise ValueError(f"Unsupported rules version: {version_raw!r} (expected 1 or 2)") from exc
    if version not in (1, 2):
        raise ValueError(f"Unsupported rules version: {version!r} (expected 1 or 2)")

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("'rules' must be a list")

    out: list[Rule] = []
    for idx, raw in enumerate(raw_rules):
        rule = _parse_rule(raw, index=idx, rules_path=rules_path, strict=strict)
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


def _parse_rule(raw: Any, *, index: int, rules_path: Path, strict: bool) -> Rule | None:
    if not isinstance(raw, dict):
        return _invalid_rule(index=index, description="", strict=strict, reason="not_an_object")

    description = str(raw.get("description") or "")

    trigger_raw = raw.get("trigger", "")
    if trigger_raw is None:
        trigger = ""
    elif isinstance(trigger_raw, str):
        trigger = trigger_raw
    else:
        return _invalid_rule(
            index=index,
            description=description,
            strict=strict,
            reason="trigger_not_string",
        )

    search = raw.get("search")
    if not isinstance(search, str) or not search:
        return _invalid_rule(index=index, description=description, strict=strict, reason="missing_search")

    enabled_raw = raw.get("enable", raw.get("enabled", None))
    enabled = _normalize_enabled(enabled_raw, default=True)

    action: RuleAction | None = None
    replacement = ""
    if "action" in raw and raw.get("action") is not None:
        try:
            action = parse_action(raw.get("action"))
        except Exception as exc:
            return _invalid_rule(
                index=index,
                description=description,
                strict=strict,
                reason="invalid_action",
                error=str(exc),
            )
    elif "replace" in raw:
        replace = raw.get("replace")
        if replace is None:
            replacement = ""
        elif isinstance(replace, str):
            replacement = replace
        else:
            return _invalid_rule(
                index=index,
                description=description,
                strict=strict,
                reason="replace_not_string",
            )
        action = ReplacementAction(value=replacement)
    else:
        return _invalid_rule(
            index=index,
            description=description,
            strict=strict,
            reason="missing_replace_or_action",
        )

    case_sensitive = _normalize_case_sensitive(raw.get("caseSensitive"), default=True)
    flags = 0 if case_sensitive else re.IGNORECASE

    try:
        regex = re.compile(search, flags=flags)
    except re.error as exc:
        return _invalid_rule(
            index=index,
            description=description,
            strict=strict,
            reason="invalid_regex",
            error=str(exc),
            search=search,
            path=str(rules_path),
        )

    return Rule(
        description=description,
        trigger=trigger,
        regex=regex,
        replacement=replacement,
        case_sensitive=case_sensitive,
        action=action,
        enabled=enabled,
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


def _normalize_enabled(value: Any, *, default: bool) -> bool:
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
    logger.warning("invalid_enable_value", extra={"value": str(value)})
    return default


def _invalid_rule(
    *,
    index: int,
    description: str,
    strict: bool,
    reason: str,
    error: str | None = None,
    **extra: Any,
) -> Rule | None:
    payload: dict[str, Any] = {"index": index, "reason": reason, "description": description}
    if error is not None:
        payload["error"] = error
    payload.update(extra)
    msg = "invalid_rule"
    if strict:
        # Raise with a human-readable message (CLI/UI surfaces exceptions).
        details = ", ".join(f"{k}={payload[k]!r}" for k in sorted(payload.keys()))
        raise ValueError(f"{msg}: {details}")
    logger.warning("invalid_rule_skipped", extra=payload)
    return None
