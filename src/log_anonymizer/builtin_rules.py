from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable

from log_anonymizer.rules_loader import Rule

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class BuiltinRulesConfig:
    """
    Controls built-in Hadoop ecosystem anonymization rules.
    """

    enabled: bool = True


def default_rules() -> list[Rule]:
    """
    Built-in rules for common sensitive patterns found in Hadoop ecosystem logs.

    These provide a baseline; users can override or add rules via `merge_rules()`.
    """
    rules: list[Rule] = []

    # IP addresses
    rules.append(_make("IPv4 address", trigger=".", search=r"\b(?:\d{1,3}\.){3}\d{1,3}\b", replace="[IP]"))
    rules.append(
        _make(
            "IPv6 address",
            trigger=":",
            search=r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b",
            replace="[IPV6]",
            case_sensitive=True,
        )
    )

    # Hostnames / FQDNs (very common in HDFS/YARN/Spark logs)
    rules.append(
        _make(
            "Hostname/FQDN",
            trigger=".",
            search=r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:[A-Za-z]{2,63})\b",
            replace="[HOST]",
        )
    )

    # Kerberos principals: service/host@REALM and user@REALM
    rules.append(
        _make(
            "Kerberos service principal",
            trigger="@",
            search=r"\b[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\b",
            replace="[KRB_PRINCIPAL]",
        )
    )
    rules.append(
        _make(
            "Kerberos user principal",
            trigger="@",
            search=r"\b[A-Za-z0-9._-]+@[A-Za-z0-9._-]+\b",
            replace="[KRB_USER]",
        )
    )

    # Usernames (common conventions)
    rules.append(
        _make(
            "user=...",
            trigger="user=",
            search=r"\buser\s*=\s*([A-Za-z0-9._-]+)\b",
            replace="user=[USER]",
            case_sensitive=False,
        )
    )
    rules.append(
        _make(
            "username=...",
            trigger="username=",
            search=r"\busername\s*=\s*([A-Za-z0-9._-]+)\b",
            replace="username=[USER]",
            case_sensitive=False,
        )
    )
    rules.append(
        _make(
            "uid=...",
            trigger="uid=",
            search=r"\buid\s*=\s*([A-Za-z0-9._-]+)\b",
            replace="uid=[USER]",
            case_sensitive=False,
        )
    )

    # HDFS-style user paths
    rules.append(
        _make(
            "/user/<name>/ path",
            trigger="/user/",
            search=r"(?i)(/user/)([A-Za-z0-9._-]+)(/)",
            replace=r"\1[USER]\3",
            case_sensitive=True,
        )
    )

    # Generic absolute file paths (Linux-like). This is intentionally conservative to avoid over-redaction.
    rules.append(
        _make(
            "Absolute file path",
            trigger="/",
            search=r"(?<![A-Za-z0-9_])/(?:[A-Za-z0-9._-]+/){2,}[A-Za-z0-9._-]+",
            replace="[PATH]",
        )
    )

    return rules


def merge_rules(*, builtin: Iterable[Rule], user: Iterable[Rule]) -> list[Rule]:
    """
    Merge built-in and user rules.

    Override behavior:
    - If a user rule has the same `description` as a built-in rule, the user rule replaces it.
    - Otherwise, user rules are appended (so they can further transform/redact).
    """
    builtin_list = list(builtin)
    user_list = list(user)

    builtin_by_desc: dict[str, int] = {}
    for idx, r in enumerate(builtin_list):
        if r.description:
            builtin_by_desc[r.description] = idx

    merged = list(builtin_list)
    for ur in user_list:
        if ur.description and ur.description in builtin_by_desc:
            merged[builtin_by_desc[ur.description]] = ur
        else:
            merged.append(ur)
    return merged


def _make(
    description: str,
    *,
    trigger: str,
    search: str,
    replace: str,
    case_sensitive: bool = True,
) -> Rule:
    flags = 0 if case_sensitive else re.IGNORECASE
    try:
        regex = re.compile(search, flags=flags)
    except re.error as exc:
        # Built-ins should not be invalid; if they are, fail fast with context.
        raise RuntimeError(f"Invalid built-in rule regex ({description}): {exc}") from exc
    return Rule(
        description=description,
        trigger=trigger,
        regex=regex,
        replacement=replace,
        case_sensitive=case_sensitive,
    )

