"""The one definition of "a new JVM started here", shared by the parsers and segments.py.

A new JVM run starts at:

* a JVM startup header ("CommandLine flags:" for Java 8, "Using <collector>" for unified
  logging), unless Java 8 GC log rotation wrote it (rotation repeats the header);
* JVM uptime going back by more than ``UPTIME_RESTART_TOLERANCE_SECONDS``;
* a different process id (unified logs that carry both pid and tid decorators).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal

# Why a new run started: its startup header, uptime going back, or another process id
type RestartReason = Literal["header", "uptime", "pid"]

# "-XX:+PrintCommandLineFlags" prints the same flags without the prefix, to stdout (so into
# Tomcat's catalina.out), once per JVM start: a line of nothing but -XX: options
PRINTED_FLAGS_LINE = r"^-XX:\S+(?:\s+-XX:\S+)*\s*$"
JVM_START_HEADER: re.Pattern[str] = re.compile(
    r"^CommandLine flags:|\]\s*Using (?:G1|Parallel|Serial|Concurrent Mark Sweep)\s*$|"
    + PRINTED_FLAGS_LINE
)
# Java 8 GC log rotation (hotspot ostream.cpp, gcLogFileStream::rotate_log_impl) writes
# "<time> GC log file created <file>" (NumberOfGCLogFiles > 1) or "File  <file> rotated at
# <time>" (one file, rewound), then repeats the startup header: VM version, "Memory:" and
# "CommandLine flags:". A header that follows such a marker continues the same JVM.
JAVA8_ROTATION_MARKER: re.Pattern[str] = re.compile(
    r" GC log file created |^File  \S.* rotated at "
)
ROTATION_HEADER_MAX_DISTANCE = 3  # lines from the marker to "CommandLine flags:"
# Lines from different threads can be written a few ms out of order; a real restart goes
# back to (nearly) zero
UPTIME_RESTART_TOLERANCE_SECONDS = 1.0


def uptime_went_back(previous: float | None, current: float | None) -> bool:
    """True when ``current`` uptime is too far below ``previous`` to be the same JVM."""
    if previous is None or current is None:
        return False
    return current < previous - UPTIME_RESTART_TOLERANCE_SECONDS


def pid_changed(previous: int | None, current: int | None) -> bool:
    """True when both process ids are known and differ."""
    return previous is not None and current is not None and previous != current


class HeaderScanner:
    """Finds JVM startup headers line by line, leaving out those repeated by rotation."""

    __slots__ = ("_last_rotation_marker",)

    def __init__(self) -> None:
        self._last_rotation_marker: int | None = None

    def is_start_header(self, index: int, line: str) -> bool:
        """True when line ``index`` (0-based, fed in order) starts a new JVM run."""
        # substring checks first: this runs on every line of the log
        if ("GC log file created" in line or line.startswith("File  ")) and (
            JAVA8_ROTATION_MARKER.search(line)
        ):
            self._last_rotation_marker = index
            return False
        if not (line.startswith(("CommandLine flags:", "-XX:")) or "Using " in line):
            return False
        if not JVM_START_HEADER.search(line.rstrip()):
            return False
        marker = self._last_rotation_marker
        return marker is None or index - marker > ROTATION_HEADER_MAX_DISTANCE


def find_header_lines(lines: Iterable[str]) -> list[int]:
    """1-based line numbers of JVM startup headers (rotation repeats of the header excluded)."""
    scanner = HeaderScanner()
    return [index + 1 for index, line in enumerate(lines) if scanner.is_start_header(index, line)]


class RestartDetector:
    """Line-by-line restart detection for a parser that links lines by GC id."""

    __slots__ = ("_headers", "_index", "_last_pid", "_last_uptime")

    def __init__(self) -> None:
        self._headers = HeaderScanner()
        self._index = 0
        self._last_uptime: float | None = None
        self._last_pid: int | None = None

    def restarted(self, line: str, uptime: float | None, pid: int | None) -> RestartReason | None:
        """Feed the next line; why a new JVM run starts on it, or None when none does.

        The header is written after some startup lines of the same run (G1 prints its region
        size first), so a "header" restart must not discard what those lines said.
        """
        header = self._headers.is_start_header(self._index, line)
        reason: RestartReason | None = None
        if pid_changed(self._last_pid, pid):
            reason = "pid"
        elif uptime_went_back(self._last_uptime, uptime):
            reason = "uptime"
        elif header:
            reason = "header"
        self._index += 1
        if uptime is not None:
            self._last_uptime = uptime
        if pid is not None:
            self._last_pid = pid
        return reason
