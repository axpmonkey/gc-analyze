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


def compute_candidate_coverage(
    log_lines: list[str], raw_events: list[dict[str, Any]], label: str | None = None
) -> CandidateCoverage:
    """Count candidate GC lines and how many of them fall inside a parsed record."""
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
    for line_index, line in enumerate(log_lines):
        if not is_gc_candidate_line(line):
            continue
        candidates += 1
        if line_index in covered:
            parsed += 1
        elif len(samples) < UNPARSED_SAMPLE_LIMIT:
            text = line.strip()
            if len(text) > UNPARSED_SAMPLE_MAX_CHARS:
                text = text[: UNPARSED_SAMPLE_MAX_CHARS - 3] + "..."
            samples.append(f"{prefix}L{line_index + 1}: {text}")
    return CandidateCoverage(
        candidate_lines=candidates,
        parsed_candidate_lines=parsed,
        unparsed_samples=samples,
        total_lines=len(log_lines),
        continuation_lines=continuation,
    )


def merge_coverage(parts: list[CandidateCoverage]) -> CandidateCoverage:
    """Combine per-file coverage into one total."""
    samples = [s for part in parts for s in part.unparsed_samples][:UNPARSED_SAMPLE_LIMIT]
    return CandidateCoverage(
        candidate_lines=sum(p.candidate_lines for p in parts),
        parsed_candidate_lines=sum(p.parsed_candidate_lines for p in parts),
        unparsed_samples=samples,
        total_lines=sum(p.total_lines for p in parts),
        continuation_lines=sum(p.continuation_lines for p in parts),
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
