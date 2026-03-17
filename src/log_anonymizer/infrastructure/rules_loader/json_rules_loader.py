from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from log_anonymizer.domain.rules import (
    AnonymizationRule,
    HashConfig,
    RuleAction,
    RuleSet,
)


@dataclass(frozen=True)
class JsonRulesLoader:
    path: Path

    def load(self) -> RuleSet:
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("Rules JSON must be an object.")

        version = int(data.get("version", 0))
        if version != 1:
            raise ValueError(f"Unsupported rules version: {version}")

        hash_data = data.get("hash") or {}
        hash_config = HashConfig(
            prefix=str(hash_data.get("prefix", "anon_")),
            length=int(hash_data.get("length", 16)),
        )
        if hash_config.length < 8 or hash_config.length > 64:
            raise ValueError("hash.length must be between 8 and 64.")

        rules_raw = data.get("rules")
        if not isinstance(rules_raw, list) or not rules_raw:
            raise ValueError("Rules JSON must contain a non-empty 'rules' array.")

        rules: list[AnonymizationRule] = []
        for idx, item in enumerate(rules_raw):
            if not isinstance(item, dict):
                raise ValueError(f"Rule at index {idx} must be an object.")

            name = str(item.get("name") or f"rule_{idx}")
            pattern_str = item.get("pattern")
            if not isinstance(pattern_str, str) or not pattern_str:
                raise ValueError(f"Rule '{name}' is missing 'pattern'.")

            action_str = item.get("action")
            if not isinstance(action_str, str):
                raise ValueError(f"Rule '{name}' is missing 'action'.")
            action = RuleAction(action_str)

            flags = _parse_flags(item.get("flags"))
            pattern = re.compile(pattern_str, flags=flags)

            replacement = item.get("replacement")
            token = item.get("token")
            if action == RuleAction.REPLACE:
                if not isinstance(replacement, str):
                    raise ValueError(f"Rule '{name}' requires string 'replacement'.")
            if action == RuleAction.TOKEN:
                if not isinstance(token, str):
                    raise ValueError(f"Rule '{name}' requires string 'token'.")

            rules.append(
                AnonymizationRule(
                    name=name,
                    pattern=pattern,
                    action=action,
                    replacement=replacement if isinstance(replacement, str) else None,
                    token=token if isinstance(token, str) else None,
                    flags=flags,
                )
            )

        return RuleSet(version=version, rules=tuple(rules), hash_config=hash_config)


def _parse_flags(raw: Any) -> int:
    if raw is None:
        return 0
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        mapping = {
            "I": re.IGNORECASE,
            "IGNORECASE": re.IGNORECASE,
            "M": re.MULTILINE,
            "MULTILINE": re.MULTILINE,
            "S": re.DOTALL,
            "DOTALL": re.DOTALL,
        }
        flags = 0
        parts = [p.strip().upper() for p in raw.split("|") if p.strip()]
        for p in parts:
            if p not in mapping:
                raise ValueError(f"Unknown regex flag: {p}")
            flags |= mapping[p]
        return flags
    raise ValueError("flags must be int or string (e.g., 'IGNORECASE|MULTILINE').")

