"""Parsing coverage: GC-event-like lines found vs. lines turned into events.

Silent drops are the main reason analyzer output can't be trusted, so every run reports
how many lines looked like GC pauses, how many became events, how many were folded into
multi-line records, and samples of the ones that were not understood.
"""

from __future__ import annotations

import re
from typing import Any

from .models import CandidateCoverage

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
UNIFIED_DURATION_SUFFIX: re.Pattern[str] = re.compile(r"[\d.]+\s*ms$")
UNPARSED_SAMPLE_LIMIT = 5
UNPARSED_SAMPLE_MAX_CHARS = 160
UNPARSED_WARNING_THRESHOLD_PCT = 1.0
# Unified "gc,start" opener of a pause ("GC(7) Pause Young (Normal) ..."); the same text
# ending in a duration is the finished pause.
UNIFIED_PAUSE_OPENER: re.Pattern[str] = re.compile(r"\bGC\((\d+)\) Pause \S")
TRUNCATION_LOOKBACK_LINES = 400


def is_gc_candidate_line(line: str) -> bool:
    """Return True if the line looks like a GC pause record, whether or not it parses."""
    if not line or line[0].isspace():
        return False  # indented lines are details of the record above
    if line.startswith("CommandLine flags:"):  # e.g. "-XX:+UseParNewGC" contains "ParNew"
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


def find_truncated_final_record(log_lines: list[str], covered: set[int]) -> int | None:
    """0-based index of a GC record the log stops in the middle of, if it ends that way.

    A JVM that is killed, crashes or hangs during a collection leaves the record unfinished:
    a Java 8 record cut off before its closing bracket, or a unified "Pause ..." opener with
    no matching line carrying the duration.
    """
    last = len(log_lines) - 1
    while last >= 0 and not log_lines[last].strip():
        last -= 1
    if last < 0:
        return None
    line = log_lines[last]
    if not UNIFIED_GC_ID_LINE.search(line):
        unfinished = line.count("[") > line.count("]")
        if last not in covered and unfinished and is_gc_candidate_line(line):
            return last
        return None
    finished: set[str] = set()
    for index in range(last, max(-1, last - TRUNCATION_LOOKBACK_LINES), -1):
        text = log_lines[index].rstrip()
        match = UNIFIED_PAUSE_OPENER.search(text)
        if match is None:
            continue
        if UNIFIED_DURATION_SUFFIX.search(text):
            finished.add(match.group(1))
        elif match.group(1) not in finished:
            return index
    return None


def compute_candidate_coverage(
    log_lines: list[str], raw_events: list[dict[str, Any]], label: str | None = None
) -> CandidateCoverage:
    """Count candidate GC lines and how many of them fall inside a parsed record.

    A record the log stops in the middle of is also named in ``truncated_final_record``. It
    still counts as unparsed: a cut-off record and a garbled one cannot be told apart for
    certain, and an unparsed line must never be hidden.
    """
    covered: set[int] = set()
    continuation = 0
    for event in raw_events:
        if "line_index" not in event:
            continue
        start = int(event["line_index"])
        end = int(event.get("line_end", start))
        covered.update(range(start, end + 1))
        continuation += end - start

    candidates = 0
    parsed = 0
    samples: list[str] = []
    prefix = f"{label}:" if label else ""
    truncated = find_truncated_final_record(log_lines, covered)
    for line_index, line in enumerate(log_lines):
        if not is_gc_candidate_line(line):
            continue
        candidates += 1
        if line_index in covered:
            parsed += 1
        elif len(samples) < UNPARSED_SAMPLE_LIMIT:
            samples.append(_sample(line_index, line, prefix))
    return CandidateCoverage(
        candidate_lines=candidates,
        parsed_candidate_lines=parsed,
        unparsed_samples=samples,
        total_lines=len(log_lines),
        continuation_lines=continuation,
        truncated_final_record=(
            _sample(truncated, log_lines[truncated], prefix) if truncated is not None else None
        ),
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
