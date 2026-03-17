from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Callable, Iterable

from log_anonymizer.domain.rules import AnonymizationRule, HashConfig, RuleAction
from log_anonymizer.utils.hashing import stable_hash

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AnonymizationEngine:
    rules: tuple[AnonymizationRule, ...]
    hash_config: HashConfig
    salt: str

    def anonymize_text(self, text: str) -> str:
        out = text
        for rule in self.rules:
            out = self._apply_rule(rule, out)
        return out

    def anonymize_lines(self, lines: Iterable[str]) -> Iterable[str]:
        for line in lines:
            yield self.anonymize_text(line)

    def _apply_rule(self, rule: AnonymizationRule, text: str) -> str:
        if rule.action == RuleAction.REPLACE:
            assert rule.replacement is not None
            return rule.pattern.sub(rule.replacement, text)

        if rule.action == RuleAction.TOKEN:
            assert rule.token is not None
            return rule.pattern.sub(rule.token, text)

        if rule.action == RuleAction.MASK:
            return rule.pattern.sub(lambda m: "*" * len(m.group(0)), text)

        if rule.action == RuleAction.HASH:
            return rule.pattern.sub(self._hash_repl(rule.pattern), text)

        raise ValueError(f"Unsupported action: {rule.action}")

    def _hash_repl(self, pattern: re.Pattern[str]) -> Callable[[re.Match[str]], str]:
        prefix = self.hash_config.prefix
        length = self.hash_config.length

        def _repl(match: re.Match[str]) -> str:
            raw = match.group(0)
            digest = stable_hash(raw, salt=self.salt, length=length)
            return f"{prefix}{digest}"

        return _repl

