from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from typing import Any, Callable, Protocol


@dataclass(frozen=True)
class ActionContext:
    """
    Runtime context for rule actions.

    Notes:
    - Salt is optional to preserve backward compatibility and keep CLI/UI behavior unchanged.
    - For strong pseudonymization, configure a stable salt (e.g. via config) and keep it secret.
    """

    salt: str = ""


ReplacementCallable = Callable[[re.Match[str]], str]
Replacement = str | ReplacementCallable


class RuleAction(Protocol):
    type: str

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement: ...


@dataclass(frozen=True)
class ReplacementAction:
    type: str = "replacement"
    value: str = ""

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        return self.value


@dataclass(frozen=True)
class RedactionAction:
    type: str = "redaction"

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        return ""


@dataclass(frozen=True)
class MaskAction:
    type: str = "mask"
    mask_char: str = "*"
    keep_first: int = 0
    keep_last: int = 0

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        mask_char = self.mask_char
        keep_first = self.keep_first
        keep_last = self.keep_last

        def _repl(match: re.Match[str]) -> str:
            raw = match.group(0)
            if not raw:
                return raw
            n = len(raw)
            left = min(max(keep_first, 0), n)
            right = min(max(keep_last, 0), n - left)
            middle = n - left - right
            if middle <= 0:
                return raw
            return raw[:left] + (mask_char * middle) + raw[n - right :]

        return _repl


@dataclass(frozen=True)
class SecureHashAction:
    type: str = "secure_hash"
    algorithm: str = "sha256"
    salt: str | None = None
    length: int = 32
    prefix: str = "[HASH:"
    suffix: str = "]"

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        algo = self.algorithm.lower().strip()
        salt = context.salt if self.salt is None else self.salt
        length = self.length
        prefix = self.prefix
        suffix = self.suffix

        def _repl(match: re.Match[str]) -> str:
            raw = match.group(0)
            h = hashlib.new(algo)
            h.update(salt.encode("utf-8", errors="replace"))
            h.update(b":")
            h.update(raw.encode("utf-8", errors="replace"))
            digest = h.hexdigest()
            if length is not None:
                digest = digest[:length]
            return f"{prefix}{digest}{suffix}"

        return _repl


@dataclass(frozen=True)
class DateShiftAction:
    type: str = "date_shift"
    formats: tuple[str, ...] = ("%Y-%m-%d",)
    max_shift_days: int = 30
    salt: str | None = None
    group: int = 0

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        formats = self.formats
        max_shift = self.max_shift_days
        salt = context.salt if self.salt is None else self.salt
        group = self.group

        def _shift_days(raw: str) -> int:
            # Deterministic shift in [-max_shift, +max_shift].
            if max_shift <= 0:
                return 0
            h = hashlib.sha256()
            h.update(salt.encode("utf-8", errors="replace"))
            h.update(b":")
            h.update(rule_key.encode("utf-8", errors="replace"))
            h.update(b":")
            h.update(raw.encode("utf-8", errors="replace"))
            val = int(h.hexdigest()[:8], 16)
            span = (2 * max_shift) + 1
            return (val % span) - max_shift

        def _try_parse(raw: str) -> tuple[datetime | date, str] | None:
            for fmt in formats:
                try:
                    # Keep as datetime when format contains time fields; otherwise use date.
                    dt = datetime.strptime(raw, fmt)
                    if any(token in fmt for token in ("%H", "%M", "%S", "%f")):
                        return dt, fmt
                    return dt.date(), fmt
                except ValueError:
                    continue
            return None

        def _repl(match: re.Match[str]) -> str:
            raw = match.group(group)
            parsed = _try_parse(raw)
            if parsed is None:
                return match.group(0)
            value, fmt = parsed
            shifted = value + timedelta(days=_shift_days(raw))
            rendered = shifted.strftime(fmt)
            if group == 0:
                return rendered
            return _replace_group_text(match, group=group, replacement=rendered)

        return _repl


@dataclass(frozen=True)
class Bucket:
    min: float
    max: float
    label: str

    def contains(self, value: float) -> bool:
        return self.min <= value <= self.max


@dataclass(frozen=True)
class BucketAction:
    type: str = "bucket"
    buckets: tuple[Bucket, ...] = ()
    group: int = 0
    fallback_label: str = "[BUCKET]"

    def as_replacement(self, *, context: ActionContext, rule_key: str) -> Replacement:
        buckets = self.buckets
        group = self.group
        fallback = self.fallback_label

        def _bucket_for(v: float) -> str:
            for b in buckets:
                if b.contains(v):
                    return b.label
            return fallback

        def _repl(match: re.Match[str]) -> str:
            raw = match.group(group)
            try:
                val = float(raw)
            except ValueError:
                return match.group(0)
            label = _bucket_for(val)
            if group == 0:
                return label
            return _replace_group_text(match, group=group, replacement=label)

        return _repl


def parse_action(raw: Any) -> RuleAction:
    if not isinstance(raw, dict):
        raise ValueError("action must be an object")

    action_type = raw.get("type")
    if not isinstance(action_type, str) or not action_type.strip():
        raise ValueError("action.type must be a non-empty string")
    action_type = action_type.strip()

    if action_type == "replacement":
        value = raw.get("value", "")
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise ValueError("action.value must be a string")
        return ReplacementAction(value=value)

    if action_type == "redaction":
        return RedactionAction()

    if action_type == "mask":
        mask_char = raw.get("maskChar", "*")
        if not isinstance(mask_char, str) or not mask_char:
            raise ValueError("action.maskChar must be a non-empty string")
        # Keep behavior simple/predictable: enforce single character.
        if len(mask_char) != 1:
            raise ValueError("action.maskChar must be a single character")
        keep_last = raw.get("keepLast", 0)
        keep_first = raw.get("keepFirst", 0)
        if not isinstance(keep_last, int) or keep_last < 0:
            raise ValueError("action.keepLast must be an int >= 0")
        if not isinstance(keep_first, int) or keep_first < 0:
            raise ValueError("action.keepFirst must be an int >= 0")
        return MaskAction(mask_char=mask_char, keep_first=keep_first, keep_last=keep_last)

    if action_type == "secure_hash":
        algo = raw.get("algorithm", "sha256")
        if not isinstance(algo, str) or not algo.strip():
            raise ValueError("action.algorithm must be a non-empty string")
        algo = algo.strip().lower()
        if algo != "sha256":
            raise ValueError("action.algorithm currently supports only 'sha256'")

        salt = raw.get("salt")
        if salt is not None and not isinstance(salt, str):
            raise ValueError("action.salt must be a string")

        length = raw.get("length", 32)
        if not isinstance(length, int) or length < 8 or length > 64:
            raise ValueError("action.length must be an int between 8 and 64")

        prefix = raw.get("prefix", "[HASH:")
        suffix = raw.get("suffix", "]")
        if not isinstance(prefix, str):
            raise ValueError("action.prefix must be a string")
        if not isinstance(suffix, str):
            raise ValueError("action.suffix must be a string")

        return SecureHashAction(algorithm=algo, salt=salt, length=length, prefix=prefix, suffix=suffix)

    if action_type == "date_shift":
        formats_raw = raw.get("formats")
        if formats_raw is None:
            formats: tuple[str, ...] = ("%Y-%m-%d",)
        else:
            if not isinstance(formats_raw, list) or not formats_raw:
                raise ValueError("action.formats must be a non-empty array of strings")
            formats = tuple(str(f) for f in formats_raw if str(f))
            if not formats:
                raise ValueError("action.formats must contain non-empty strings")

        max_shift = raw.get("maxShiftDays", 30)
        if not isinstance(max_shift, int) or max_shift < 0 or max_shift > 36525:
            raise ValueError("action.maxShiftDays must be an int between 0 and 36525")

        salt = raw.get("salt")
        if salt is not None and not isinstance(salt, str):
            raise ValueError("action.salt must be a string")

        group = raw.get("group", 0)
        if not isinstance(group, int) or group < 0:
            raise ValueError("action.group must be an int >= 0")

        return DateShiftAction(formats=formats, max_shift_days=max_shift, salt=salt, group=group)

    if action_type == "bucket":
        buckets_raw = raw.get("buckets")
        if not isinstance(buckets_raw, list) or not buckets_raw:
            raise ValueError("action.buckets must be a non-empty array")

        buckets: list[Bucket] = []
        for idx, b in enumerate(buckets_raw):
            if not isinstance(b, dict):
                raise ValueError(f"action.buckets[{idx}] must be an object")
            if "min" not in b or "max" not in b:
                raise ValueError(f"action.buckets[{idx}] must include 'min' and 'max'")
            try:
                b_min = float(b["min"])
                b_max = float(b["max"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"action.buckets[{idx}].min/max must be numeric") from exc
            if b_min > b_max:
                raise ValueError(f"action.buckets[{idx}] has min > max")
            label = b.get("label")
            if not isinstance(label, str) or not label:
                raise ValueError(f"action.buckets[{idx}].label must be a non-empty string")
            buckets.append(Bucket(min=b_min, max=b_max, label=label))

        # Reject overlapping buckets to keep mapping deterministic/predictable.
        buckets_sorted = sorted(buckets, key=lambda x: (x.min, x.max))
        for prev, cur in zip(buckets_sorted, buckets_sorted[1:], strict=False):
            if cur.min <= prev.max:
                raise ValueError("action.buckets must not overlap")

        group = raw.get("group", 0)
        if not isinstance(group, int) or group < 0:
            raise ValueError("action.group must be an int >= 0")

        fallback = raw.get("fallbackLabel", "[BUCKET]")
        if not isinstance(fallback, str) or not fallback:
            raise ValueError("action.fallbackLabel must be a non-empty string")

        return BucketAction(buckets=tuple(buckets_sorted), group=group, fallback_label=fallback)

    raise ValueError(f"Unknown action.type: {action_type!r}")


def _replace_group_text(match: re.Match[str], *, group: int, replacement: str) -> str:
    """
    Replace only a capturing group's text while still using `re.sub` (which replaces group 0).

    This is useful for rules that match e.g. "age=23" and want to replace only the numeric value.
    """
    whole = match.group(0)
    g_start, g_end = match.span(group)
    m_start, _ = match.span(0)
    rel_start = g_start - m_start
    rel_end = g_end - m_start
    if rel_start < 0 or rel_end < rel_start or rel_end > len(whole):
        # Should not happen for valid match objects, but keep failure mode safe.
        return whole
    return whole[:rel_start] + replacement + whole[rel_end:]


def ensure_action_compatible_with_legacy_replace(action: RuleAction, legacy_replace: str | None) -> RuleAction:
    """
    Legacy rules use `replace` directly; new rules use `action`.

    If both are provided, prefer `action` (explicit) and ignore `replace`.
    This helper exists to keep all legacy parsing decisions in one place.
    """
    return action


def describe_supported_actions() -> list[str]:
    # Used by docs/tests for a stable list.
    return ["replacement", "redaction", "mask", "secure_hash", "date_shift", "bucket"]
