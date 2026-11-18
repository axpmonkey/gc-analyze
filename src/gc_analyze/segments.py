"""Multiple input files and JVM restarts.

A file (or a set of rotated files) can span several JVM runs. Mixing them corrupts rates,
trends and floors, so events are split into segments. What counts as a new JVM run is
defined once, in jvm_runs.py: a startup header between two events (not one repeated by
Java 8 log rotation), uptime going back, or a different process id. Files are ordered by
first wall-clock time, else first uptime; the next file continues the segment only when
its time continues forward.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path

from .jvm_runs import pid_changed, uptime_went_back
from .models import CandidateCoverage, GCEvent, SegmentInfo, SideRecord
from .parsers import GCParser
from .scan import FileScan


@dataclass
class LoadedFile:
    """One parsed input file."""

    path: Path
    parser: GCParser
    coverage: CandidateCoverage
    facts: FileScan  # what the single reading pass kept (no log lines)
    events: list[GCEvent] = field(default_factory=list[GCEvent])

    @property
    def total_lines(self) -> int:
        """Lines in the file."""
        return self.facts.total_lines

    @property
    def header_line_numbers(self) -> list[int]:
        """1-based line numbers of JVM startup headers."""
        return self.facts.header_line_numbers

    @property
    def side_records(self) -> list[SideRecord]:
        """Concurrent phases, safepoints and pause-goal misses, in line order."""
        return self.facts.side_records

    @property
    def first_event(self) -> GCEvent | None:
        """First event in line order."""
        return self.events[0] if self.events else None


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
    """True when ``event`` can belong to the same JVM run as ``previous`` (see jvm_runs.py)."""
    if pid_changed(previous.pid, event.pid):
        return False
    if previous.uptime_seconds is not None and event.uptime_seconds is not None:
        return not uptime_went_back(previous.uptime_seconds, event.uptime_seconds)
    if previous.wall_clock and event.wall_clock:
        return event.timestamp >= previous.timestamp
    return True


def assign_segments(files: list[LoadedFile]) -> tuple[list[GCEvent], list[SegmentInfo]]:
    """Tag every event with its segment; return them all (file order, then line order).

    Each file's ``events`` is replaced by its tagged events, so no second copy is kept.
    """
    segment = 1
    previous: GCEvent | None = None
    tagged: list[GCEvent] = []
    for loaded in files:
        headers = loaded.header_line_numbers
        file_events: list[GCEvent] = []
        prior_line = 0
        for event in loaded.events:
            this_line = event.line_number or 0
            if previous is not None and (
                not _continues(previous, event) or any(prior_line < h < this_line for h in headers)
            ):
                segment += 1
            segmented = event if event.segment == segment else replace(event, segment=segment)
            file_events.append(segmented)
            previous, prior_line = segmented, this_line
        loaded.events = file_events
        tagged.extend(file_events)
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
    """Keep pauses that overlap [start, end].

    A long pause that began before ``start`` or finished after ``end`` still stopped the
    application inside the window, so it is kept; the summary only counts the part inside.
    """
    return [
        e
        for e in events
        if (start is None or e.pause_end > start) and (end is None or e.pause_start < end)
    ]
