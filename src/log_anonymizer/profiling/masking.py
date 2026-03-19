from __future__ import annotations

import re


def mask_email(value: str) -> str:
    v = value.strip()
    if "@" not in v:
        return "[EMAIL]"
    local, domain = v.split("@", 1)
    local = local.strip()
    domain = domain.strip()
    if not domain:
        return "[EMAIL]"
    if not local:
        return f"***@{domain}"
    return f"{local[:1]}***@{domain}"


_ipv4_rx = re.compile(r"^(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})$")


def mask_ipv4(value: str) -> str:
    m = _ipv4_rx.match(value.strip())
    if not m:
        return "[IP]"
    a = m.group("a")
    d = m.group("d")
    return f"{a}.***.***.{d}"


def mask_token(value: str) -> str:
    v = value.strip()
    if len(v) <= 8:
        return "***"
    head = v[:3]
    tail = v[-4:]
    return f"{head}-***{tail}"


def mask_card_number(value: str) -> str:
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) < 4:
        return "****"
    return f"**** **** **** {digits[-4:]}"

