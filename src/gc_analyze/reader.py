"""Reading log files line by line without holding them in memory.

``LineWindow`` gives parsers indexed access to the lines around the one they are reading
(a legacy record and the detail lines after it) while keeping only the most recent
``WINDOW_LINES``. Every line is handed once, in order, to an optional ``on_line`` callback as
it is read, so the other per-line scanners share the same single pass.
"""

from __future__ import annotations

import gzip
from collections import deque
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import TextIO

# Lines kept behind the newest one read. Must exceed the farthest any parser looks back from
# the newest line it has read: a legacy record (40 lines) plus the [Times: ...] and
# Heap-after-GC lookahead after it (80 + 16), and the 400 lines read for format detection.
WINDOW_LINES = 2048
GZIP_MAGIC = b"\x1f\x8b"


def open_log(path: Path) -> TextIO:
    """Open a GC log as text, decompressing it when it is gzip (rotated ``gc.log.3.gz``)."""
    with path.open("rb") as probe:
        compressed = probe.read(2) == GZIP_MAGIC
    if compressed:
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open(encoding="utf-8", errors="replace")


class LineWindow:
    """Lines of a log read on demand; only the newest ``capacity`` lines are kept."""

    __slots__ = ("_buffer", "_count", "_exhausted", "_first", "_on_line", "_source")

    def __init__(
        self,
        source: Iterable[str],
        *,
        capacity: int = WINDOW_LINES,
        on_line: Callable[[int, str], None] | None = None,
    ) -> None:
        self._source: Iterator[str] = iter(source)
        self._buffer: deque[str] = deque(maxlen=capacity)
        self._first = 0  # index of the oldest line still in the buffer
        self._count = 0  # lines read from the source so far
        self._exhausted = False
        self._on_line = on_line

    @property
    def lines_read(self) -> int:
        """How many lines have been read from the source so far."""
        return self._count

    def _read_through(self, index: int) -> bool:
        if index < self._count:
            return True
        buffer, on_line, capacity = self._buffer, self._on_line, self._buffer.maxlen
        while self._count <= index and not self._exhausted:
            line = next(self._source, None)
            if line is None:
                self._exhausted = True
                break
            if on_line is not None:
                on_line(self._count, line)
            if len(buffer) == capacity:
                self._first += 1
            buffer.append(line)
            self._count += 1
        return index < self._count

    def get(self, index: int) -> str | None:
        """Line ``index`` (0-based), or None past the end of the log."""
        if index >= self._count and not self._read_through(index):
            return None
        if index < self._first:
            raise IndexError(f"line {index + 1} has left the window (oldest kept: {self._first})")
        return self._buffer[index - self._first]

    def __getitem__(self, index: int) -> str:
        line = self.get(index)
        if line is None:
            raise IndexError(index)
        return line

    def range(self, start: int, stop: int) -> list[str]:
        """Lines ``start`` up to (not including) ``stop`` that exist."""
        lines: list[str] = []
        for index in range(start, stop):
            line = self.get(index)
            if line is None:
                break
            lines.append(line)
        return lines

    def __iter__(self) -> Iterator[str]:
        index = 0
        while (line := self.get(index)) is not None:
            yield line
            index += 1

    def read_to_end(self) -> int:
        """Read (and hand to ``on_line``) every remaining line; return the line count."""
        while self._read_through(self._count):
            pass
        return self._count


type LineSource = LineWindow | Iterable[str]


def as_window(lines: LineSource) -> LineWindow:
    """``lines`` itself when it is a window; otherwise a window over it (lists, iterators)."""
    return lines if isinstance(lines, LineWindow) else LineWindow(lines)


def read_lines_at(path: Path, wanted: Iterable[int]) -> dict[int, str]:
    """Lines at the given 0-based indexes, read again from the file (stops after the last)."""
    remaining = sorted(set(wanted))
    found: dict[int, str] = {}
    if not remaining:
        return found
    last = remaining[-1]
    targets = set(remaining)
    with open_log(path) as handle:
        for index, line in enumerate(handle):
            if index in targets:
                found[index] = line
            if index >= last:
                break
    return found
