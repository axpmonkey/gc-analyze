"""Per-line facts gathered in the same single pass as parsing (see reader.LineWindow).

Nothing here keeps the log's lines: only JVM startup headers, side records (concurrent
phases, safepoints), coverage candidates, the last lines of the file, the few lines that
state JVM configuration, and time markers at the positions where a JVM run can begin or end.
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field

from .coverage import TRUNCATION_TAIL_LINES, is_gc_candidate_line
from .jvm_runs import HeaderScanner, uptime_went_back
from .models import SideRecord
from .parsers import log_line_times, side_record_for

# "GC(3) Using 8 workers of 8 for evacuation" is written for every collection; only the first
# after each run boundary (or a change of value) is kept for the JVM configuration.
_WORKERS = re.compile(r"Using\s+\d+\s+workers?\s+of\s+(\d+)")

type TimedLine = tuple[int, str]  # (line index, datestamp as logged; parsed only when used)
type UptimeLine = tuple[int, float]


@dataclass(slots=True)
class TimeMark:
    """The timed lines nearest to a position where a JVM run can start or end.

    A line with a datestamp counts as timed; a line with only an uptime counts once a
    wall-clock anchor for its run is known (pipeline.py). Datestamps are kept as logged and
    parsed only for the few markers a run boundary uses.
    """

    stamp_before: TimedLine | None  # last datestamped line before the position
    uptime_before: UptimeLine | None  # last uptime-only line before it
    stamp_from: TimedLine | None = None  # first datestamped line at or after it
    uptime_from: UptimeLine | None = None  # first uptime-only line at or after it


def _is_config_line(line: str) -> bool:
    """Lines jvm_config.py reads (except the per-collection workers line)."""
    return (
        line.startswith(("-XX:", "Memory: "))
        or "CommandLine flags" in line
        or "[gc,init" in line
        or "Heap Max Capacity" in line
        or "Heap address:" in line
        or "egion size" in line
        or (" VM (" in line and " JRE (" in line)
    )


@dataclass(slots=True)
class FileScan:
    """Facts about one log file, collected line by line as the parser reads it."""

    source_file: str
    total_lines: int = 0
    header_line_numbers: list[int] = field(default_factory=list[int])  # 1-based
    gc_init_line_numbers: list[int] = field(default_factory=list[int])  # 1-based
    side_records: list[SideRecord] = field(default_factory=list[SideRecord])
    candidate_lines: list[int] = field(default_factory=list[int])  # 0-based
    config_lines: list[tuple[int, str]] = field(default_factory=list[tuple[int, str]])
    tail: deque[tuple[int, str]] = field(
        default_factory=lambda: deque[tuple[int, str]](maxlen=TRUNCATION_TAIL_LINES)
    )
    time_marks: dict[int, TimeMark] = field(default_factory=dict[int, TimeMark])
    _headers: HeaderScanner = field(default_factory=HeaderScanner)
    _last_stamp: TimedLine | None = None
    _last_uptime_line: UptimeLine | None = None
    _last_uptime: float | None = None
    _waiting_stamp: list[TimeMark] = field(default_factory=list[TimeMark])
    _waiting_uptime: list[TimeMark] = field(default_factory=list[TimeMark])
    _workers_kept: str | None = None  # value of the last kept workers line
    _boundary_since_workers: bool = True

    def on_line(self, index: int, line: str) -> None:
        """Take line ``index`` (0-based); lines arrive once each, in order."""
        self.total_lines = index + 1
        self.tail.append((index, line))
        boundary = index == 0
        if self._headers.is_start_header(index, line):
            self.header_line_numbers.append(index + 1)
            boundary = True
        if "[gc,init" in line:
            self.gc_init_line_numbers.append(index + 1)
            boundary = True
        if (record := side_record_for(index, line)) is not None:
            self.side_records.append(record.model_copy(update={"source_file": self.source_file}))
        candidate = is_gc_candidate_line(line)
        if candidate:
            self.candidate_lines.append(index)

        stamp, uptime = log_line_times(line)
        if uptime_went_back(self._last_uptime, uptime):
            boundary = True
        if uptime is not None:
            self._last_uptime = uptime
        self._keep_config(line, boundary)
        if boundary or candidate:
            mark = TimeMark(self._last_stamp, self._last_uptime_line)
            self.time_marks[index] = mark
            self._waiting_stamp.append(mark)
            self._waiting_uptime.append(mark)
        self._take_time(index, stamp, uptime)

    def _keep_config(self, line: str, boundary: bool) -> None:
        if boundary:
            self._boundary_since_workers = True
        if _is_config_line(line):
            self.config_lines.append((self.total_lines - 1, line))
        elif (
            "workers" in line
            and (match := _WORKERS.search(line))
            and (self._boundary_since_workers or match.group(1) != self._workers_kept)
        ):
            self.config_lines.append((self.total_lines - 1, line))
            self._workers_kept = match.group(1)
            self._boundary_since_workers = False

    def _take_time(self, index: int, stamp: str | None, uptime: float | None) -> None:
        if stamp is not None:
            self._last_stamp = (index, stamp)
            for mark in self._waiting_stamp:
                mark.stamp_from = self._last_stamp
            self._waiting_stamp.clear()
        elif uptime is not None:
            self._last_uptime_line = (index, uptime)
            for mark in self._waiting_uptime:
                mark.uptime_from = self._last_uptime_line
            self._waiting_uptime.clear()

    def finish(self) -> None:
        """Mark the end of the file (a run's range can end there)."""
        self.time_marks[self.total_lines] = TimeMark(self._last_stamp, self._last_uptime_line)
        self._waiting_stamp.clear()
        self._waiting_uptime.clear()
