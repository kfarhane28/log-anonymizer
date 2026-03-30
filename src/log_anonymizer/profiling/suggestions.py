from __future__ import annotations

from typing import Any


def _rule_base(
    *,
    description: str,
    trigger: str | None,
    caseSensitive: bool | None,
    search: str,
) -> dict[str, Any]:
    obj: dict[str, Any] = {"description": description, "search": search}
    if trigger is not None:
        obj["trigger"] = trigger
    if caseSensitive is not None:
        obj["caseSensitive"] = caseSensitive
    return obj


def _replacement_rule(
    *,
    description: str,
    trigger: str | None,
    caseSensitive: bool | None,
    search: str,
    value: str,
) -> dict[str, Any]:
    obj = _rule_base(
        description=description,
        trigger=trigger,
        caseSensitive=caseSensitive,
        search=search,
    )
    obj["action"] = {"type": "replacement", "value": value}
    return obj


def _mask_rule(
    *,
    description: str,
    trigger: str | None,
    caseSensitive: bool | None,
    search: str,
    keepFirst: int,
    keepLast: int = 0,
    group: int = 0,
    maskChar: str = "*",
) -> dict[str, Any]:
    obj = _rule_base(
        description=description,
        trigger=trigger,
        caseSensitive=caseSensitive,
        search=search,
    )
    obj["action"] = {
        "type": "mask",
        "maskChar": maskChar,
        "keepFirst": int(keepFirst),
        "keepLast": int(keepLast),
        "group": int(group),
    }
    return obj


def suggest_rules(detected_kinds: set[str]) -> list[dict[str, Any]]:
    rules: list[dict[str, Any]] = []

    if "email" in detected_kinds:
        rules.append(
            _mask_rule(
                description="Mask email addresses",
                trigger="@",
                caseSensitive=True,
                # Mask only the local-part so the output matches the profiler example (e.g. c***@example.com).
                search=r"\b([A-Za-z0-9._%+-]+)(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b",
                keepFirst=1,
                group=1,
            )
        )

    if "ipv4" in detected_kinds:
        rules.append(
            _replacement_rule(
                description="Mask IPv4 addresses",
                trigger=".",
                caseSensitive=True,
                # Match 4 octets and replace middle octets to match profiler example (e.g. 10.***.***.80).
                search=r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b",
                value=r"\1.***.***.\4",
            )
        )

    if "bearer_token" in detected_kinds:
        rules.append(
            _replacement_rule(
                description="Mask Bearer tokens",
                trigger="Bearer ",
                caseSensitive=False,
                search=r"\bBearer\s+\S+\b",
                value="Bearer [REDACTED]",
            )
        )

    if "kv_secret" in detected_kinds:
        rules.append(
            _replacement_rule(
                description="Mask common key/value secrets (token/api_key/secret/password)",
                trigger="=",
                caseSensitive=False,
                search=r"\b(api[_-]?key|token|secret|password)\s*=\s*([^\s\"']+)\b",
                value=r"\1=[REDACTED]",
            )
        )

    if "card_number" in detected_kinds:
        rules.append(
            _replacement_rule(
                description="Mask probable card numbers (heuristic; consider tightening for your logs)",
                trigger="",
                caseSensitive=True,
                search=r"\b(?:\d[ -]*?){13,19}\b",
                value="[CARD]",
            )
        )

    if "probable_token" in detected_kinds:
        rules.append(
            _replacement_rule(
                description="Mask long probable tokens (heuristic; may cause false positives)",
                trigger="",
                caseSensitive=True,
                search=r"\b[A-Za-z0-9+/=_-]{24,}\b",
                value="[REDACTED_TOKEN]",
            )
        )

    return rules


def suggested_rules_json(detected_kinds: set[str]) -> dict[str, Any]:
    # Use rules schema v2 so we can express masking strategies precisely (keepFirst/keepLast, group masking, etc.).
    return {"version": 2, "rules": suggest_rules(detected_kinds)}
