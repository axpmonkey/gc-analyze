"""Multiple input files and JVM restarts (P1.9).

A file (or a set of rotated files) can span several JVM runs. Mixing them corrupts rates,
trends and floors, so events are split into segments:

* within one file, a new segment starts when uptime goes backwards, or when a JVM start
  header ("CommandLine flags:" for Java 8, "Using <collector>" for unified logging) appears
  after GC events;
* across files (ordered by first wall-clock time, else first uptime), the next file
  continues the segment only when its uptime (or wall-clock time) continues forward.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import CandidateCoverage, GCEvent, SegmentInfo
from .parsers import GCParser

JVM_START_HEADER: re.Pattern[str] = re.compile(
    r"^CommandLine flags:|\]\s*Using (?:G1|Parallel|Serial|Concurrent Mark Sweep)\s*$"
)


@dataclass
class LoadedFile:
    """One parsed input file."""

    path: Path
    lines: list[str]
    parser: GCParser
    raw_events: list[dict[str, Any]]
    coverage: CandidateCoverage
    events: list[GCEvent] = field(default_factory=list[GCEvent])
    header_line_numbers: list[int] = field(default_factory=list[int])  # 1-based

    @property
    def first_event(self) -> GCEvent | None:
        """First event in line order."""
        return self.events[0] if self.events else None


def find_header_lines(lines: list[str]) -> list[int]:
    """1-based line numbers of JVM start headers."""
    return [i + 1 for i, line in enumerate(lines) if JVM_START_HEADER.search(line.rstrip())]


def order_files(files: list[LoadedFile]) -> list[LoadedFile]:
    """Order files by first wall-clock time when every file has one, else by first uptime."""
    with_events = [f for f in files if f.first_event is not None]
    if len(with_events) < 2:
        return files

    def first(f: LoadedFile) -> GCEvent:
        event = f.first_event
        assert event is not None
        return event

    if all(first(f).wall_clock for f in with_events):
        key = {id(f): first(f).timestamp.timestamp() for f in with_events}
    else:
        key = {id(f): first(f).uptime_seconds or 0.0 for f in with_events}
    ordered = sorted(with_events, key=lambda f: key[id(f)])
    return ordered + [f for f in files if f.first_event is None]


def _continues(previous: GCEvent, event: GCEvent) -> bool:
    """True when ``event`` can belong to the same JVM run as ``previous`` (time goes on)."""
    if previous.uptime_seconds is not None and event.uptime_seconds is not None:
        return event.uptime_seconds >= previous.uptime_seconds
    if previous.wall_clock and event.wall_clock:
        return event.timestamp >= previous.timestamp
    return True


def assign_segments(files: list[LoadedFile]) -> tuple[list[GCEvent], list[SegmentInfo]]:
    """Return all events (file order, then line order) tagged with segment numbers."""
    segment = 1
    previous: GCEvent | None = None
    tagged: list[GCEvent] = []
    for loaded in files:
        headers = loaded.header_line_numbers
        for index, event in enumerate(loaded.events):
            if previous is not None:
                restart = not _continues(previous, event)
                if index > 0 and not restart:
                    prior_line = loaded.events[index - 1].line_number or 0
                    this_line = event.line_number or 0
                    restart = any(prior_line < h < this_line for h in headers)
                if restart:
                    segment += 1
            segmented = event.model_copy(update={"segment": segment})
            tagged.append(segmented)
            previous = segmented
    return tagged, describe_segments(tagged)


def describe_segments(events: list[GCEvent]) -> list[SegmentInfo]:
    """Summarize each segment."""
    by_segment: dict[int, list[GCEvent]] = {}
    for event in events:
        by_segment.setdefault(event.segment, []).append(event)
    infos: list[SegmentInfo] = []
    for index, seg_events in sorted(by_segment.items()):
        first, last = seg_events[0], seg_events[-1]
        files = list(dict.fromkeys(e.source_file for e in seg_events if e.source_file))
        infos.append(
            SegmentInfo(
                index=index,
                first_timestamp=first.timestamp,
                last_timestamp=last.timestamp,
                wall_clock=first.wall_clock,
                first_uptime_seconds=first.uptime_seconds,
                last_uptime_seconds=last.uptime_seconds,
                events=len(seg_events),
                files=files,
            )
        )
    return infos


def select_segment(
    events: list[GCEvent], segments: list[SegmentInfo], choice: str
) -> tuple[list[GCEvent], str]:
    """Pick events for ``choice`` ("latest", "all" or a 1-based number); return a label."""
    if choice == "all" or len(segments) <= 1:
        label = "all segments" if len(segments) > 1 else "single JVM run"
        return events, label
    if choice == "latest":
        number = segments[-1].index
    else:
        try:
            number = int(choice)
        except ValueError as exc:
            raise ValueError(
                f"--segment must be 'latest', 'all' or a number, not {choice!r}"
            ) from exc
        if not any(s.index == number for s in segments):
            raise ValueError(f"--segment {number}: the input has segments 1-{len(segments)}")
    return [e for e in events if e.segment == number], f"segment {number} of {len(segments)}"


def filter_window(
    events: list[GCEvent], start: datetime | None, end: datetime | None
) -> list[GCEvent]:
    """Keep events with start <= timestamp <= end (P2.2)."""
    return [
        e
        for e in events
        if (start is None or e.timestamp >= start) and (end is None or e.timestamp <= end)
    ]
