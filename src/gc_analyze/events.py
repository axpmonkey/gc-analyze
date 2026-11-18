"""Normalization of raw parser dicts into GCEvent, plus size helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from .models import GCEvent, PauseRecord

# Anchor for uptime-only logs without --jvm-start. Only differences between timestamps are
# meaningful; display code checks GCEvent.wall_clock before printing a date.
UPTIME_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

HEAP_AFTER_ABOVE_COMMITTED = "heap after GC above committed heap"
OLD_AFTER_ABOVE_CAPACITY = "old generation after GC above its capacity"

_OFFSET_SUFFIX = re.compile(r"(?:[+-]\d{2}:?\d{2}|Z)$")


def parse_log_timestamp(timestamp_str: str) -> datetime:
    """Parse a GC log datestamp ("2016-08-23T02:23:07.219-0200", "...Z", "...+00:00").

    A datestamp without a UTC offset is taken as UTC (``timestamp_has_offset`` tells callers).
    """
    text = timestamp_str.strip().replace("Z", "+00:00").replace(",", ".")
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
    record: PauseRecord,
    jvm_start: datetime | None = None,
    source_file: str | None = None,
) -> GCEvent:
    """Turn a parser's ``PauseRecord`` into a ``GCEvent``.

    Events without a wall-clock timestamp are placed at ``jvm_start + uptime`` when an
    anchor is given, otherwise at ``UPTIME_EPOCH + uptime`` with ``wall_clock=False``.
    Events without heap sizes are kept (their pause still counts) with
    ``has_heap_data=False``.
    """
    timestamp_str = record.timestamp
    uptime = record.uptime
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

    # Values that cannot all be true are reported and left out of the statistics they would
    # distort; they are never clamped into plausible-looking numbers.
    inconsistencies = list(record.data_inconsistencies)
    heap_total = record.heap_total or 0
    has_heap = heap_total > 0
    if has_heap and (record.heap_after or 0) > heap_total:
        inconsistencies.append(HEAP_AFTER_ABOVE_COMMITTED)
        has_heap = False  # the pause still counts; its heap sizes do not
    heap_before = (record.heap_before or 0) if has_heap else 0
    heap_after = (record.heap_after or 0) if has_heap else 0
    heap_total = heap_total if has_heap else 0

    old_total, old_after = record.old_total, record.old_after
    old_used_pct = None
    if old_total and old_total > 0 and old_after is not None:
        if old_after > old_total:
            inconsistencies.append(OLD_AFTER_ABOVE_CAPACITY)
        else:
            old_used_pct = old_after / old_total * 100

    line_index = record.line_index
    return GCEvent(
        timestamp=timestamp,
        uptime_seconds=uptime,
        gc_kind=record.gc_kind,
        wall_clock=wall_clock,
        timestamp_raw=timestamp_str,
        tz_source=tz_source,
        pause_time_seconds=record.pause,
        stamp_at_pause_end=record.stamp_at_pause_end,
        cause=record.cause or None,
        has_heap_data=has_heap,
        heap_before_kb=heap_before,
        heap_after_kb=heap_after,
        heap_total_kb=heap_total,
        young_before_kb=record.young_before,
        young_after_kb=record.young_after,
        old_before_kb=record.old_before,
        old_after_kb=old_after,
        old_total_kb=old_total,
        old_used_percentage=old_used_pct,
        concurrent_start=record.concurrent_start,
        humongous_before_kb=record.humongous_before,
        humongous_after_kb=record.humongous_after,
        promoted_kb=record.promoted,
        humongous_detected=record.humongous_detected,
        evacuation_failed=record.evacuation_failed,
        to_space_exhausted=record.to_space_exhausted,
        evacuation_failure_reason=record.evacuation_failure_reason
        or ("Allocation" if record.to_space_exhausted else None),
        concurrent_mode_failure=record.concurrent_mode_failure,
        promotion_failed=record.promotion_failed,
        metaspace_before_kb=record.metaspace_before,
        metaspace_after_kb=record.metaspace_after,
        cpu_user_seconds=record.cpu_user,
        cpu_sys_seconds=record.cpu_sys,
        cpu_real_seconds=record.cpu_real,
        survivor_capacity_kb=record.survivor_capacity,
        survivor_used_percentage=record.survivor_used_pct,
        source_file=source_file,
        line_number=line_index + 1 if line_index is not None else None,
        data_inconsistencies=tuple(inconsistencies),
        pid=record.pid,
    )


def parse_size_to_kb(size_text: str) -> int:
    """Parse a JVM size token like '1024K', '1.5M', '0.0B' into KB."""
    match = re.fullmatch(r"(?P<value>[\d.,]+)(?P<unit>[BKMG])", size_text.strip())
    if not match:
        raise ValueError(f"Unrecognized size token: {size_text}")
    value = float(match.group("value").replace(",", "."))
    unit = match.group("unit")
    if unit == "B":
        return int(value / 1024)
    if unit == "K":
        return int(value)
    if unit == "M":
        return int(value * 1024)
    return int(value * 1024 * 1024)
