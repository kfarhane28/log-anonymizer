from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Pattern


class RuleAction(str, Enum):
    HASH = "hash"
    MASK = "mask"
    TOKEN = "token"
    REPLACE = "replace"


@dataclass(frozen=True)
class HashConfig:
    prefix: str = "anon_"
    length: int = 16


@dataclass(frozen=True)
class AnonymizationRule:
    name: str
    pattern: Pattern[str]
    action: RuleAction
    replacement: str | None = None
    token: str | None = None
    flags: int = 0


@dataclass(frozen=True)
class RuleSet:
    version: int
    rules: tuple[AnonymizationRule, ...]
    hash_config: HashConfig

