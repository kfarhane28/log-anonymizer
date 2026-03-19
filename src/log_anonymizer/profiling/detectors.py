from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Protocol

from log_anonymizer.profiling.masking import (
    mask_card_number,
    mask_email,
    mask_ipv4,
    mask_token,
)


@dataclass(frozen=True)
class Detection:
    detector: str
    kind: str
    masked_example: str


class SensitivePatternDetector(Protocol):
    name: str
    kinds: tuple[str, ...]

    def detect(self, line: str) -> Iterable[Detection]: ...


class EmailDetector:
    name = "email"
    kinds = ("email",)

    def __init__(self) -> None:
        self._rx = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def detect(self, line: str) -> Iterable[Detection]:
        if "@" not in line:
            return []
        out: list[Detection] = []
        for m in self._rx.finditer(line):
            out.append(Detection(detector=self.name, kind="email", masked_example=mask_email(m.group(0))))
        return out


class IPv4Detector:
    name = "ipv4"
    kinds = ("ipv4",)

    def __init__(self) -> None:
        self._rx = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    def detect(self, line: str) -> Iterable[Detection]:
        if "." not in line:
            return []
        out: list[Detection] = []
        for m in self._rx.finditer(line):
            out.append(Detection(detector=self.name, kind="ipv4", masked_example=mask_ipv4(m.group(0))))
        return out


class TokenDetector:
    name = "token"
    kinds = ("bearer_token", "kv_secret", "probable_token")

    def __init__(self) -> None:
        self._bearer = re.compile(r"\bBearer\s+([A-Za-z0-9._-]{10,})\b", flags=re.IGNORECASE)
        self._kv = re.compile(
            r"\b(api[_-]?key|token|secret|password)\s*=\s*([^\s\"']{8,})\b",
            flags=re.IGNORECASE,
        )
        self._probable = re.compile(r"\b[A-Za-z0-9+/=_-]{24,}\b")

    @staticmethod
    def _is_probably_token(s: str) -> bool:
        if len(s) < 24:
            return False
        has_alpha = any(ch.isalpha() for ch in s)
        has_digit = any(ch.isdigit() for ch in s)
        return has_alpha and has_digit

    def detect(self, line: str) -> Iterable[Detection]:
        out: list[Detection] = []

        if "bearer" in line.lower():
            for m in self._bearer.finditer(line):
                tok = m.group(1)
                out.append(
                    Detection(detector=self.name, kind="bearer_token", masked_example=f"Bearer {mask_token(tok)}")
                )

        if "=" in line:
            for m in self._kv.finditer(line):
                key = m.group(1)
                val = m.group(2)
                out.append(
                    Detection(detector=self.name, kind="kv_secret", masked_example=f"{key}={mask_token(val)}")
                )

        for m in self._probable.finditer(line):
            tok = m.group(0)
            if not self._is_probably_token(tok):
                continue
            out.append(Detection(detector=self.name, kind="probable_token", masked_example=mask_token(tok)))

        return out


class CardNumberDetector:
    name = "card"
    kinds = ("card_number",)

    def __init__(self) -> None:
        self._rx = re.compile(r"\b(?:\d[ -]*?){13,19}\b")

    @staticmethod
    def _luhn_ok(number: str) -> bool:
        digits = [int(ch) for ch in number if ch.isdigit()]
        if len(digits) < 13 or len(digits) > 19:
            return False
        checksum = 0
        parity = len(digits) % 2
        for i, d in enumerate(digits):
            if i % 2 == parity:
                d2 = d * 2
                checksum += (d2 - 9) if d2 > 9 else d2
            else:
                checksum += d
        return (checksum % 10) == 0

    def detect(self, line: str) -> Iterable[Detection]:
        out: list[Detection] = []
        for m in self._rx.finditer(line):
            raw = m.group(0)
            digits = "".join(ch for ch in raw if ch.isdigit())
            if not digits:
                continue
            if not self._luhn_ok(digits):
                continue
            out.append(
                Detection(detector=self.name, kind="card_number", masked_example=mask_card_number(digits))
            )
        return out


def default_detectors() -> dict[str, SensitivePatternDetector]:
    detectors: list[SensitivePatternDetector] = [
        EmailDetector(),
        IPv4Detector(),
        TokenDetector(),
        CardNumberDetector(),
    ]
    return {d.name: d for d in detectors}

