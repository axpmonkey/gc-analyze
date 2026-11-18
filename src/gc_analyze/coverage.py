"""Parsing coverage: GC-event-like lines found vs. lines turned into events.

Silent drops are the main reason analyzer output can't be trusted, so every run reports
how many lines looked like GC pauses, how many became events, how many were folded into
multi-line records, and samples of the ones that were not understood.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Sequence

from .models import CandidateCoverage, PauseRecord

# Substrings that mark a line as a GC pause record, across collectors and log formats.
GC_CANDIDATE_MARKERS: tuple[str, ...] = (
    "[GC ",
    "[GC(",
    "[Full GC",
    "Pause Young",
    "Pause Mixed",
    "Pause Full",
    "Pause Initial Mark",
    "Pause Remark",
    "Pause Cleanup",
    "GC pause",
    "ParNew",
    "DefNew",
    "CMS-initial-mark",
    "CMS-remark",
    "[GC remark",
    "[GC cleanup",
)
# Legacy G1 concurrent-phase fragments ("[GC concurrent-mark-end, 0.01 secs]") are not pauses.
LEGACY_CONCURRENT_FRAGMENT: re.Pattern[str] = re.compile(r"\[GC concurrent-[^\]]*\]")
# Unified logging line carrying a GC id. Only the line ending in a duration is the pause
# record; "gc,start" openers and gc,heap detail lines for the same GC id are not.
UNIFIED_GC_ID_LINE: re.Pattern[str] = re.compile(r"^\[[^\]]*\].*\bGC\(\d+\)")
UNIFIED_DURATION_SUFFIX: re.Pattern[str] = re.compile(r"[\d.,]+\s*ms$")
UNPARSED_SAMPLE_LIMIT = 5
UNPARSED_SAMPLE_MAX_CHARS = 160
UNPARSED_WARNING_THRESHOLD_PCT = 1.0
# Unified "gc,start" opener of a pause ("GC(7) Pause Young (Normal) ..."); the same text
# ending in a duration is the finished pause.
UNIFIED_PAUSE_OPENER: re.Pattern[str] = re.compile(r"\bGC\((\d+)\) Pause \S")
TRUNCATION_LOOKBACK_LINES = 400
# Lines kept from the end of each file: the lookback plus room for trailing blank lines
TRUNCATION_TAIL_LINES = TRUNCATION_LOOKBACK_LINES + 112


def is_gc_candidate_line(line: str) -> bool:
    """Return True if the line looks like a GC pause record, whether or not it parses."""
    if not line or line[0].isspace():
        return False  # indented lines are details of the record above
    if line.startswith("CommandLine flags:"):  # e.g. "-XX:+UseParNewGC" contains "ParNew"
        return False
    if "[gc,exit" in line or "[gc,heap,exit" in line:
        return False  # the heap summary printed at JVM exit ("DefNew total 19648K, used ...")
    # every marker contains one of these; most lines of a catalina.out contain none
    if not ("GC" in line or "Pause" in line or "New" in line or "CMS-" in line):
        return False
    text = LEGACY_CONCURRENT_FRAGMENT.sub("", line) if "[GC concurrent-" in line else line
    if not any(marker in text for marker in GC_CANDIDATE_MARKERS):
        return False
    if UNIFIED_GC_ID_LINE.search(text):
        return UNIFIED_DURATION_SUFFIX.search(text.rstrip()) is not None
    return True


def _sample(line_index: int, line: str, prefix: str) -> str:
    text = line.strip()
    if len(text) > UNPARSED_SAMPLE_MAX_CHARS:
        text = text[: UNPARSED_SAMPLE_MAX_CHARS - 3] + "..."
    return f"{prefix}L{line_index + 1}: {text}"


def find_truncated_final_record(
    tail: Sequence[tuple[int, str]], is_covered: Callable[[int], bool]
) -> int | None:
    """0-based index of a GC record the log stops in the middle of, if it ends that way.

    ``tail`` is the last lines of the file as (index, line). A JVM that is killed, crashes
    or hangs during a collection leaves the record unfinished: a Java 8 record cut off
    before its closing bracket, or a unified "Pause ..." opener with no matching line
    carrying the duration.
    """
    lines = [(index, line) for index, line in tail]
    while lines and not lines[-1][1].strip():
        lines.pop()
    if not lines:
        return None
    last, line = lines[-1]
    if not UNIFIED_GC_ID_LINE.search(line):
        unfinished = line.count("[") > line.count("]")
        if not is_covered(last) and unfinished and is_gc_candidate_line(line):
            return last
        return None
    finished: set[str] = set()
    for index, text in reversed(lines[-TRUNCATION_LOOKBACK_LINES:]):
        match = UNIFIED_PAUSE_OPENER.search(text.rstrip())
        if match is None:
            continue
        if UNIFIED_DURATION_SUFFIX.search(text.rstrip()):
            finished.add(match.group(1))
        elif match.group(1) not in finished:
            return index
    return None


class CoveredLines:
    """Whether a line falls inside a parsed record, from the records' line ranges."""

    __slots__ = ("_ends", "_starts")

    def __init__(self, records: Sequence[PauseRecord]) -> None:
        ranges = sorted(
            (
                record.line_index,
                record.line_end if record.line_end is not None else record.line_index,
            )
            for record in records
            if record.line_index is not None
        )
        self._starts = [start for start, _ in ranges]
        # running maximum of the ends, so one bisect answers "inside any range?"
        self._ends: list[int] = []
        furthest = -1
        for _, end in ranges:
            furthest = max(furthest, end)
            self._ends.append(furthest)

    def __call__(self, index: int) -> bool:
        position = bisect_right(self._starts, index) - 1
        return position >= 0 and self._ends[position] >= index


def coverage_from_scan(
    candidate_lines: Sequence[int],
    tail: Sequence[tuple[int, str]],
    total_lines: int,
    records: Sequence[PauseRecord],
    sample_text: Callable[[list[int]], dict[int, str]],
    label: str | None = None,
) -> CandidateCoverage:
    """Count candidate GC lines and how many of them fall inside a parsed record.

    ``sample_text`` returns the text of the given 0-based lines; it is called only for the
    few unparsed lines quoted as samples, so the log need not be kept in memory.
    A record the log stops in the middle of is also named in ``truncated_final_record``. It
    still counts as unparsed: a cut-off record and a garbled one cannot be told apart for
    certain, and an unparsed line must never be hidden.
    """
    covered = CoveredLines(records)
    continuation = sum(
        record.line_end - record.line_index
        for record in records
        if record.line_index is not None and record.line_end is not None
    )
    unparsed = [index for index in candidate_lines if not covered(index)]
    sampled = unparsed[:UNPARSED_SAMPLE_LIMIT]
    truncated = find_truncated_final_record(tail, covered)
    wanted = sampled + ([truncated] if truncated is not None else [])
    texts = sample_text(wanted) if wanted else {}
    prefix = f"{label}:" if label else ""
    return CandidateCoverage(
        candidate_lines=len(candidate_lines),
        parsed_candidate_lines=len(candidate_lines) - len(unparsed),
        unparsed_samples=[_sample(index, texts.get(index, ""), prefix) for index in sampled],
        total_lines=total_lines,
        continuation_lines=continuation,
        truncated_final_record=(
            _sample(truncated, texts.get(truncated, ""), prefix) if truncated is not None else None
        ),
    )


def compute_candidate_coverage(
    log_lines: Sequence[str], records: Sequence[PauseRecord], label: str | None = None
) -> CandidateCoverage:
    """``coverage_from_scan`` for lines already in memory."""
    return coverage_from_scan(
        [index for index, line in enumerate(log_lines) if is_gc_candidate_line(line)],
        list(enumerate(log_lines))[-TRUNCATION_TAIL_LINES:],
        len(log_lines),
        records,
        lambda wanted: {index: log_lines[index] for index in wanted},
        label,
    )


def merge_coverage(parts: list[CandidateCoverage]) -> CandidateCoverage:
    """Combine per-file coverage into one total (``parts`` in time order).

    Only the last file can show where logging stopped: an earlier rotated file that ends
    mid-record continues in the next one.
    """
    samples = [s for part in parts for s in part.unparsed_samples][:UNPARSED_SAMPLE_LIMIT]
    return CandidateCoverage(
        candidate_lines=sum(p.candidate_lines for p in parts),
        parsed_candidate_lines=sum(p.parsed_candidate_lines for p in parts),
        unparsed_samples=samples,
        total_lines=sum(p.total_lines for p in parts),
        continuation_lines=sum(p.continuation_lines for p in parts),
        truncated_final_record=parts[-1].truncated_final_record if parts else None,
    )


def build_unparsed_warning(coverage: CandidateCoverage | None) -> str | None:
    """Return a top-of-report warning when too many candidate lines went unparsed."""
    if coverage is None or coverage.unparsed_percentage <= UNPARSED_WARNING_THRESHOLD_PCT:
        return None
    return (
        f"WARNING: {coverage.unparsed_candidate_lines} of {coverage.candidate_lines} "
        f"GC event lines ({coverage.unparsed_percentage:.1f}%) were not recognized by the "
        "parser. All counts, rates and percentiles in this report exclude them. "
        "See Parsing Coverage for sample lines."
    )
