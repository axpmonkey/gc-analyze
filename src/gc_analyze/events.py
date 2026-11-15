"""Normalization of raw parser dicts into GCEvent, plus size helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

from .models import GCEvent

# Anchor for uptime-only logs without --jvm-start. Only differences between timestamps are
# meaningful; display code checks GCEvent.wall_clock before printing a date.
UPTIME_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

_OFFSET_SUFFIX = re.compile(r"(?:[+-]\d{2}:?\d{2}|Z)$")


def parse_log_timestamp(timestamp_str: str) -> datetime:
    """Parse a GC log datestamp ("2016-08-23T02:23:07.219-0200", "...Z", "...+00:00").

    A datestamp without a UTC offset is taken as UTC (``timestamp_has_offset`` tells callers).
    """
    text = timestamp_str.strip().replace("Z", "+00:00")
    if re.search(r"[+-]\d{4}$", text):
        text = f"{text[:-2]}:{text[-2:]}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed


def timestamp_has_offset(timestamp_str: str) -> bool:
    """True when the log datestamp carries its own UTC offset."""
    return bool(_OFFSET_SUFFIX.search(timestamp_str.strip()))


def normalize_event(
    raw_event: dict[str, Any],
    jvm_start: datetime | None = None,
    source_file: str | None = None,
) -> GCEvent | None:
    """Convert a parser dict to a validated GCEvent.

    Events without a wall-clock timestamp are placed at ``jvm_start + uptime`` when an
    anchor is given, otherwise at ``UPTIME_EPOCH + uptime`` with ``wall_clock=False``.
    Events without heap sizes are kept (their pause still counts) with
    ``has_heap_data=False``. Returns None only for events with no usable pause time.
    """
    timestamp_str: str | None = raw_event.get("timestamp")
    uptime: float | None = raw_event.get("uptime")
    wall_clock = True
    tz_source: str | None
    if timestamp_str:
        timestamp = parse_log_timestamp(timestamp_str)
        tz_source = "in-line" if timestamp_has_offset(timestamp_str) else "assumed:UTC"
    elif jvm_start is not None and uptime is not None:
        timestamp = jvm_start + timedelta(seconds=uptime)
        tz_source = f"cli:{jvm_start.isoformat()}"
    else:
        timestamp = UPTIME_EPOCH + timedelta(seconds=uptime or 0.0)
        wall_clock = False
        tz_source = None

    pause_time = raw_event.get("pause")
    if pause_time is None:
        return None
    pause_time = max(0.0, float(pause_time))

    heap_total = int(raw_event.get("heap_total") or 0)
    has_heap = heap_total > 0
    heap_before = int(raw_event.get("heap_before") or 0) if has_heap else 0
    heap_after = int(raw_event.get("heap_after") or 0) if has_heap else 0
    heap_used_pct = max(0.0, min(100.0, heap_after / heap_total * 100)) if has_heap else 0.0

    old_total = raw_event.get("old_total")
    old_after = raw_event.get("old_after")
    old_used_pct = None
    if old_total and old_total > 0 and old_after is not None:
        old_used_pct = max(0.0, min(100.0, old_after / old_total * 100))

    line_index = raw_event.get("line_index")
    return GCEvent(
        timestamp=timestamp,
        uptime_seconds=uptime,
        gc_kind=raw_event["gc_kind"],
        wall_clock=wall_clock,
        timestamp_raw=timestamp_str,
        tz_source=tz_source,
        pause_time_seconds=pause_time,
        stamp_at_pause_end=bool(raw_event.get("stamp_at_pause_end", False)),
        cause=raw_event.get("cause") or None,
        has_heap_data=has_heap,
        heap_before_kb=heap_before,
        heap_after_kb=heap_after,
        heap_total_kb=heap_total,
        heap_used_percentage=heap_used_pct,
        young_before_kb=raw_event.get("young_before"),
        young_after_kb=raw_event.get("young_after"),
        young_total_kb=raw_event.get("young_total"),
        old_before_kb=raw_event.get("old_before"),
        old_after_kb=old_after,
        old_total_kb=old_total,
        old_used_percentage=old_used_pct,
        humongous_detected=raw_event.get("humongous_detected", False),
        evacuation_failed=raw_event.get("evacuation_failed", False),
        to_space_exhausted=raw_event.get("to_space_exhausted", False),
        concurrent_mode_failure=raw_event.get("concurrent_mode_failure", False),
        promotion_failed=raw_event.get("promotion_failed", False),
        metaspace_before_kb=raw_event.get("metaspace_before"),
        metaspace_after_kb=raw_event.get("metaspace_after"),
        metaspace_total_kb=raw_event.get("metaspace_total"),
        cpu_user_seconds=raw_event.get("cpu_user"),
        cpu_sys_seconds=raw_event.get("cpu_sys"),
        cpu_real_seconds=raw_event.get("cpu_real"),
        survivor_capacity_kb=raw_event.get("survivor_capacity"),
        survivor_used_percentage=raw_event.get("survivor_used_pct"),
        source_file=source_file,
        line_number=line_index + 1 if line_index is not None else None,
    )


def parse_size_to_kb(size_text: str) -> int:
    """Parse a JVM size token like '1024K', '1.5M', '0.0B' into KB."""
    match = re.fullmatch(r"(?P<value>[\d.]+)(?P<unit>[BKMG])", size_text.strip())
    if not match:
        raise ValueError(f"Unrecognized size token: {size_text}")
    value = float(match.group("value"))
    unit = match.group("unit")
    if unit == "B":
        return int(value / 1024)
    if unit == "K":
        return int(value)
    if unit == "M":
        return int(value * 1024)
    return int(value * 1024 * 1024)
