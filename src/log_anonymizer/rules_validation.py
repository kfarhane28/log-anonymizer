from __future__ import annotations

import json
from typing import Any

from log_anonymizer.rule_actions import parse_action


def validate_rules_json_bytes(raw: bytes) -> str | None:
    """
    Validate that rules.json bytes are UTF-8 JSON and match a supported schema.

    Supported:
    - version 1 (legacy): rule uses `search` + `replace`
    - version 2 (action-based): rule uses `search` + `action`

    Notes:
    - This is intentionally stricter than the runtime loader in non-strict mode, because UIs
      should surface configuration errors early and clearly.
    - The runtime loader (`log_anonymizer.rules_loader.load_rules`) is the source of truth.
    """
    try:
        obj = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError:
        return "not valid UTF-8"
    except json.JSONDecodeError as exc:
        return f"invalid JSON: {exc}"

    if not isinstance(obj, dict):
        return "root must be a JSON object"

    version_raw = obj.get("version", 1)
    try:
        version = int(version_raw)
    except Exception:
        return "version must be 1 or 2"
    if version not in (1, 2):
        return "version must be 1 or 2"

    rules = obj.get("rules")
    if not isinstance(rules, list):
        return "rules must be a list"

    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            return f"rules[{i}] must be an object"

        search = r.get("search")
        if not isinstance(search, str) or not search.strip():
            return f"rules[{i}].search must be a non-empty string"

        if "trigger" in r and r["trigger"] is not None and not isinstance(r["trigger"], str):
            return f"rules[{i}].trigger must be a string"
        if "description" in r and r["description"] is not None and not isinstance(r["description"], str):
            return f"rules[{i}].description must be a string"
        if "caseSensitive" in r and r["caseSensitive"] is not None and not isinstance(
            r["caseSensitive"], (str, bool, int, float)
        ):
            return f"rules[{i}].caseSensitive must be boolean or string"

        action = r.get("action")
        if action is not None:
            try:
                parse_action(action)
            except Exception as exc:
                return f"rules[{i}].action invalid: {exc}"
            continue

        # Legacy (or compatibility) path: require replace when no action is provided.
        if "replace" not in r:
            return f"rules[{i}] missing 'replace' (or provide 'action')"
        replace = r.get("replace")
        if replace is not None and not isinstance(replace, str):
            return f"rules[{i}].replace must be a string"

    return None

