from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SuggestedRule:
    description: str
    trigger: str | None
    caseSensitive: bool | None
    search: str
    replace: str

    def to_json_obj(self) -> dict[str, Any]:
        obj: dict[str, Any] = {
            "description": self.description,
            "search": self.search,
            "replace": self.replace,
        }
        if self.trigger:
            obj["trigger"] = self.trigger
        if self.caseSensitive is not None:
            obj["caseSensitive"] = self.caseSensitive
        return obj


def suggest_rules(detected_kinds: set[str]) -> list[SuggestedRule]:
    rules: list[SuggestedRule] = []

    if "email" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask email addresses",
                trigger="@",
                caseSensitive=True,
                search=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                replace="[EMAIL]",
            )
        )

    if "ipv4" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask IPv4 addresses",
                trigger=".",
                caseSensitive=True,
                search=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                replace="[IP]",
            )
        )

    if "bearer_token" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask Bearer tokens",
                trigger="Bearer ",
                caseSensitive=False,
                search=r"\bBearer\s+\S+\b",
                replace="Bearer [REDACTED]",
            )
        )

    if "kv_secret" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask common key/value secrets (token/api_key/secret/password)",
                trigger="=",
                caseSensitive=False,
                search=r"\b(api[_-]?key|token|secret|password)\s*=\s*([^\s\"']+)\b",
                replace=r"\1=[REDACTED]",
            )
        )

    if "card_number" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask probable card numbers (heuristic; consider tightening for your logs)",
                trigger="",
                caseSensitive=True,
                search=r"\b(?:\d[ -]*?){13,19}\b",
                replace="[CARD]",
            )
        )

    if "probable_token" in detected_kinds:
        rules.append(
            SuggestedRule(
                description="Mask long probable tokens (heuristic; may cause false positives)",
                trigger="",
                caseSensitive=True,
                search=r"\b[A-Za-z0-9+/=_-]{24,}\b",
                replace="[REDACTED_TOKEN]",
            )
        )

    return rules


def suggested_rules_json(detected_kinds: set[str]) -> dict[str, Any]:
    rules = [r.to_json_obj() for r in suggest_rules(detected_kinds)]
    return {"version": 1, "rules": rules}

