"""The analysis pipeline: files -> events -> segments -> window -> summary (no rendering)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from pathlib import Path

from .analysis import build_comprehensive_summary
from .coverage import compute_candidate_coverage, merge_coverage
from .events import normalize_event
from .jvm_config import parse_jvm_environment, parse_jvm_heap_config, parse_max_heap_from_log
from .models import (
    CandidateCoverage,
    DiagnosticThresholds,
    FileCoverage,
    GCEvent,
    GCSummary,
    SegmentInfo,
    SideRecord,
)
from .parsers import detect_gc_type_and_create_parser, scan_side_records
from .segments import (
    LoadedFile,
    assign_segments,
    filter_window,
    find_header_lines,
    order_files,
    select_segment,
)


class NoEventsError(ValueError):
    """No GC pauses could be parsed from the input."""

    def __init__(self, coverage: CandidateCoverage) -> None:
        super().__init__("No usable GC events found in log file")
        self.coverage = coverage


@dataclass
class AnalysisResult:
    """Everything computed for one run."""

    files: list[LoadedFile]
    gc_type: str
    coverage: CandidateCoverage
    all_events: list[GCEvent]
    segments: list[SegmentInfo]
    events: list[GCEvent]  # the analyzed window, sorted by time
    segment_label: str
    summary: GCSummary
    window_label: str | None = None
    comparison: GCSummary | None = None
    comparison_label: str = ""
    file_coverages: list[FileCoverage] = field(default_factory=list[FileCoverage])


def load_file(path: Path, jvm_start: datetime | None, label: str | None) -> LoadedFile:
    """Read, detect, parse and normalize one log file."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        lines = handle.readlines()
    try:
        parser = detect_gc_type_and_create_parser(lines)
    except ValueError as exc:
        raise ValueError(f"{path}: {exc}") from exc
    raw_events = parser.parse(lines)
    loaded = LoadedFile(
        path=path,
        lines=lines,
        parser=parser,
        raw_events=raw_events,
        coverage=compute_candidate_coverage(lines, raw_events, label),
        header_line_numbers=find_header_lines(lines),
        side_records=[
            record.model_copy(update={"source_file": str(path)})
            for record in scan_side_records(lines)
        ],
    )
    for raw in raw_events:
        if event := normalize_event(raw, jvm_start, source_file=str(path)):
            loaded.events.append(event)
    return loaded


# Lines kept before a JVM start header: the Java 8 version/memory lines and the unified
# "Heap region size" line are written just above it.
HEADER_LOOKBACK_LINES = 5


def segment_startup_lines(files: list[LoadedFile], events: list[GCEvent]) -> list[str] | None:
    """Log lines of the JVM run behind the latest analysed segment, from its start header.

    Flags and heap sizes can change between restarts, so the configuration shown must come
    from the run being analysed. Returns None when that run's header is not in its file
    (e.g. the header is in an older rotated file).
    """
    latest_segment = max(e.segment for e in events)
    first = next(e for e in events if e.segment == latest_segment)
    loaded = next((f for f in files if str(f.path) == first.source_file), None)
    if loaded is None or first.line_number is None:
        return None
    line_number = first.line_number
    headers_before = [h for h in loaded.header_line_numbers if h <= line_number]
    if not headers_before:
        return None
    headers_after = [h for h in loaded.header_line_numbers if h > line_number]
    start = max(0, headers_before[-1] - 1 - HEADER_LOOKBACK_LINES)
    end = headers_after[0] - 1 if headers_after else len(loaded.lines)
    return loaded.lines[start:end]


def side_records_between(files: list[LoadedFile], events: list[GCEvent]) -> list[SideRecord]:
    """Concurrent-work and safepoint records lying between the first and last analysed pause.

    Line position in each file stands in for time, which keeps the records to the analysed
    JVM run and --start/--end window without needing a timestamp on every line.
    """
    bounds: dict[str, tuple[int, int]] = {}
    for event in events:
        if event.source_file is None or event.line_number is None:
            continue
        low, high = bounds.get(event.source_file, (event.line_number, event.line_number))
        bounds[event.source_file] = (min(low, event.line_number), max(high, event.line_number))
    kept: list[SideRecord] = []
    for loaded in files:
        if str(loaded.path) not in bounds:
            continue
        low, high = bounds[str(loaded.path)]
        kept += [r for r in loaded.side_records if low <= r.line_number <= high]
    return kept


def parse_time_option(value: str | None, option: str, default_tz: tzinfo | None) -> datetime | None:
    """ISO 8601 time from an option; a time without offset takes ``default_tz``."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{option}: not an ISO 8601 time: {value}") from exc
    if parsed.tzinfo is None:
        if default_tz is None:
            raise ValueError(f"{option}: include a UTC offset, e.g. 2026-11-10T14:00:00-05:00")
        parsed = parsed.replace(tzinfo=default_tz)
    return parsed


def run_analysis(
    paths: list[Path],
    *,
    thresholds: DiagnosticThresholds | None = None,
    jvm_start: datetime | None = None,
    max_heap_bytes: int | None = None,
    segment: str = "latest",
    start: str | None = None,
    end: str | None = None,
) -> AnalysisResult:
    """Parse ``paths`` and analyze the chosen JVM run and time window."""
    thresholds = thresholds or DiagnosticThresholds()
    multiple = len(paths) > 1
    files = [load_file(p, jvm_start, p.name if multiple else None) for p in paths]
    gc_types = {f.parser.gc_type_name for f in files if f.events}
    if len(gc_types) > 1:
        raise ValueError(f"Input files use different collectors: {', '.join(sorted(gc_types))}")
    gc_type = next(iter(gc_types)) if gc_types else files[0].parser.gc_type_name
    files = order_files(files)
    coverage = merge_coverage([f.coverage for f in files])

    all_events, segments = assign_segments(files)
    if not all_events:
        raise NoEventsError(coverage)
    events, segment_label = select_segment(all_events, segments, segment)

    all_lines = [line for f in files for line in f.lines]
    run_lines = segment_startup_lines(files, events)
    config = (parse_jvm_heap_config(run_lines) if run_lines else None) or parse_jvm_heap_config(
        all_lines
    )
    log_max_heap = (
        parse_max_heap_from_log(run_lines) if run_lines else None
    ) or parse_max_heap_from_log(all_lines)

    environment = (parse_jvm_environment(run_lines) if run_lines else None) or (
        parse_jvm_environment(all_lines) if len(segments) == 1 else None
    )

    def summarize(
        window_events: list[GCEvent],
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> GCSummary:
        return build_comprehensive_summary(
            window_events,
            thresholds,
            gc_type=gc_type,
            jvm_heap_config=config,
            max_heap_bytes=max_heap_bytes,
            max_heap_from_log_bytes=log_max_heap,
            window_start=window_start,
            window_end=window_end,
            side_records=side_records_between(files, window_events),
            environment=environment,
        )

    log_tz = next((e.timestamp.tzinfo for e in all_events if e.wall_clock), None)
    start_dt = parse_time_option(start, "--start", log_tz)
    end_dt = parse_time_option(end, "--end", log_tz)
    window_label: str | None = None
    comparison: GCSummary | None = None
    comparison_label = ""
    if start_dt or end_dt:
        if not all(e.wall_clock for e in events):
            raise ValueError("--start/--end need wall-clock time: pass --jvm-start for this log")
        events = filter_window(events, start_dt, end_dt)
        window_label = (
            f"window {start_dt.isoformat() if start_dt else 'start'} to "
            f"{end_dt.isoformat() if end_dt else 'end'}"
        )
        if not events:
            raise ValueError(f"No GC pauses in the {window_label}")
        if start_dt and end_dt:
            day = timedelta(days=1)
            previous = filter_window(all_events, start_dt - day, end_dt - day)
            if previous:
                comparison = summarize(previous, start_dt - day, end_dt - day)
                comparison_label = "the same window 24 h earlier"

    file_coverages = [
        FileCoverage(
            path=str(f.path),
            gc_type=f.parser.gc_type_name,
            coverage=f.coverage,
            events=len(f.events),
            events_without_heap_data=sum(1 for e in f.events if not e.has_heap_data),
        )
        for f in files
    ]
    return AnalysisResult(
        files=files,
        gc_type=gc_type,
        coverage=coverage,
        all_events=all_events,
        segments=segments,
        events=sorted(events, key=lambda e: e.timestamp),
        segment_label=segment_label,
        summary=summarize(events, start_dt, end_dt),
        window_label=window_label,
        comparison=comparison,
        comparison_label=comparison_label,
        file_coverages=file_coverages,
    )
