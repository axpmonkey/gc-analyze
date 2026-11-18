"""--export-events: one JSON line per GC pause in the shared events.jsonl format.

Field rules follow work-tools/00-architecture.md: ``ts`` is UTC ISO-8601 with millisecond
precision, ``ts_raw`` keeps what the log said, ``tz_source`` records how the zone was known,
``duration_ms`` is the pause, and GC specifics go in ``attrs``.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from pathlib import Path
from typing import Any

from .analysis import classify_full_gc_cause
from .atomic import write_text_atomic
from .models import GCEvent


class ExportError(ValueError):
    """Events cannot be exported (e.g. no wall-clock time)."""


def event_level(event: GCEvent) -> str:
    """WARN for pauses that indicate trouble, INFO otherwise."""
    trouble = (
        event.concurrent_mode_failure
        or event.promotion_failed
        or event.evacuation_failed
        or (event.gc_kind == "Full" and classify_full_gc_cause(event.cause) == "heap")
    )
    return "WARN" if trouble else "INFO"


def event_record(event: GCEvent, *, host: str | None, max_heap_kb: int | None) -> dict[str, Any]:
    """Shared-format record for one pause."""
    if not event.wall_clock:
        raise ExportError(
            "--export-events needs wall-clock time: this log has uptime only; pass --jvm-start"
        )
    level = event_level(event)
    cause = event.cause or "cause not logged"
    template = f"GC pause {event.gc_kind} ({cause}) <*> ms"
    signature = "gc:" + level + ":" + hashlib.sha1(template.encode()).hexdigest()[:12]
    ts = event.timestamp.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    duration_ms = round(event.pause_time_seconds * 1000, 3)
    attrs: dict[str, Any] = {
        "kind": event.gc_kind,
        "cause": event.cause,
        "heap_before_kb": event.heap_before_kb if event.has_heap_data else None,
        "heap_after_kb": event.heap_after_kb if event.has_heap_data else None,
        "heap_committed_kb": event.heap_total_kb if event.has_heap_data else None,
        "max_heap_kb": max_heap_kb,
        "old_after_kb": event.old_after_kb,
        "uptime_s": event.uptime_seconds,
        "segment": event.segment,
        "pause_start": event.pause_start.astimezone(UTC).isoformat(),
        "pause_end": event.pause_end.astimezone(UTC).isoformat(),
    }
    if event.gc_kind == "Full":
        attrs["full_gc_category"] = classify_full_gc_cause(event.cause)
    if event.evacuation_failure_reason:
        attrs["evacuation_failure_reason"] = event.evacuation_failure_reason
    for flag in (
        "concurrent_mode_failure",
        "promotion_failed",
        "evacuation_failed",
        "humongous_detected",
    ):
        if getattr(event, flag):
            attrs[flag] = True
    return {
        "ts": ts,
        "ts_raw": event.timestamp_raw
        or (f"uptime {event.uptime_seconds:.3f}s" if event.uptime_seconds is not None else None),
        "tz_source": event.tz_source,
        "source": "gc",
        "host": host,
        "file": event.source_file,
        "line": event.line_number,
        "level": level,
        "thread": None,
        "logger": None,
        "message": f"GC pause {event.gc_kind} ({cause}) {duration_ms:g} ms",
        "exception": None,
        "stack_signature": None,
        "template": template,
        "signature": signature,
        "duration_ms": duration_ms,
        "attrs": attrs,
    }


def export_events(
    events: list[GCEvent],
    path: Path,
    *,
    host: str | None = None,
    max_heap_kb: int | None = None,
    max_heap_by_segment: dict[int, int | None] | None = None,
) -> int:
    """Write events as JSON lines; returns the number written."""
    capacities = max_heap_by_segment or {}
    records = [
        event_record(event, host=host, max_heap_kb=capacities.get(event.segment, max_heap_kb))
        for event in events
    ]
    write_text_atomic(
        path, "".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records)
    )
    return len(records)
