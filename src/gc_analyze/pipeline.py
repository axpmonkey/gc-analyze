"""The analysis pipeline: files -> events -> segments -> window -> summary (no rendering)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, tzinfo
from itertools import groupby
from pathlib import Path

from .analysis import build_comprehensive_summary, resolve_max_heap
from .coverage import compute_candidate_coverage, merge_coverage
from .events import UPTIME_EPOCH, normalize_event, parse_log_timestamp
from .jvm_config import parse_jvm_environment, parse_jvm_heap_config, parse_max_heap_from_log
from .models import (
    CandidateCoverage,
    DiagnosticThresholds,
    FileCoverage,
    GCEvent,
    GCSummary,
    JVMEnvironment,
    JVMHeapConfig,
    SegmentInfo,
    SideRecord,
)
from .parsers import detect_gc_type_and_create_parser, log_line_times, scan_side_records
from .segments import (
    LoadedFile,
    assign_segments,
    describe_segments,
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


def run_file_ranges(
    files: list[LoadedFile], events: list[GCEvent]
) -> dict[int, list[tuple[LoadedFile, int, int]]]:
    """Assign line ranges to runs using the startup headers and the segmented pauses."""
    by_file: dict[str, list[GCEvent]] = {}
    for event in events:
        if event.source_file:
            by_file.setdefault(event.source_file, []).append(event)
    ranges: dict[int, list[tuple[LoadedFile, int, int]]] = {}
    for loaded in files:
        file_events = by_file.get(str(loaded.path), [])
        previous_line = 0
        starts: list[tuple[int, int]] = []
        for segment, group in groupby(file_events, key=lambda event: event.segment):
            run_events = list(group)
            first_line = run_events[0].line_number or 1
            header = max(
                (h for h in loaded.header_line_numbers if previous_line < h <= first_line),
                default=first_line,
            )
            start = header - 1
            # Some VM startup fields immediately precede the collector announcement.
            if header in loaded.header_line_numbers:
                while start > previous_line and "[gc,init" in loaded.lines[start - 1]:
                    start -= 1
            starts.append((segment, start if starts else 0))
            previous_line = run_events[-1].line_number or first_line
        for (segment, start), (_, end) in zip(
            starts, [*starts[1:], (0, len(loaded.lines))], strict=True
        ):
            ranges.setdefault(segment, []).append((loaded, start, end))
    return ranges


def observed_wall_bounds(
    ranges: list[tuple[LoadedFile, int, int]], events: list[GCEvent]
) -> tuple[datetime, datetime]:
    """Use each range's first and last timestamped log lines, including non-pause records."""
    first = min(event.pause_start for event in events)
    last = max(event.pause_end for event in events)
    anchor = next(
        (
            event.timestamp - timedelta(seconds=event.uptime_seconds)
            for event in events
            if event.wall_clock and event.uptime_seconds is not None
        ),
        None,
    )
    for loaded, start, end in ranges:
        for indices in (range(start, end), range(end - 1, start - 1, -1)):
            for index in indices:
                stamp, uptime = log_line_times(loaded.lines[index])
                if stamp is not None:
                    try:
                        moment = parse_log_timestamp(stamp)
                    except ValueError:
                        continue
                elif anchor is not None and uptime is not None:
                    moment = anchor + timedelta(seconds=uptime)
                else:
                    continue
                first, last = min(first, moment), max(last, moment)
                break
    return first, last


def select_side_records(
    ranges: list[tuple[LoadedFile, int, int]],
    events: list[GCEvent],
    segment: int,
    start: datetime | None,
    end: datetime | None,
) -> list[SideRecord]:
    """Keep records owned by the run and overlapping the requested time bounds."""
    anchor = next(
        (
            event.timestamp - timedelta(seconds=event.uptime_seconds)
            for event in events
            if event.wall_clock and event.uptime_seconds is not None
        ),
        None,
    )
    kept: list[SideRecord] = []
    for loaded, first, last in ranges:
        for record in loaded.side_records:
            if not first < record.line_number <= last:
                continue
            moment = record.timestamp
            if moment is None and anchor is not None and record.uptime_seconds is not None:
                moment = anchor + timedelta(seconds=record.uptime_seconds)
            if start or end:
                if moment is None:
                    continue
                if start and moment <= start:
                    continue
                if end and moment - timedelta(seconds=record.seconds) >= end:
                    continue
            kept.append(record.model_copy(update={"segment": segment, "timestamp": moment}))
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

    if jvm_start is not None and len(segments) > 1:
        # One supplied anchor can only place the first JVM. Keep genuine datestamps on later runs.
        all_events = [
            event.model_copy(
                update={
                    "timestamp": event.timestamp - jvm_start + UPTIME_EPOCH,
                    "wall_clock": False,
                    "tz_source": None,
                }
            )
            if event.segment > 1
            and event.timestamp_raw is None
            and event.uptime_seconds is not None
            else event
            for event in all_events
        ]
        segments = describe_segments(all_events)
        events, segment_label = select_segment(all_events, segments, segment)
    ranges_by_run = run_file_ranges(files, all_events)
    events_by_run: dict[int, list[GCEvent]] = {}
    for event in all_events:
        events_by_run.setdefault(event.segment, []).append(event)
    configs: dict[int, JVMHeapConfig | None] = {}
    max_heap_from_log: dict[int, int | None] = {}
    max_heap_by_run: dict[int, int | None] = {}
    environments: dict[int, JVMEnvironment | None] = {}
    observed: dict[int, tuple[datetime, datetime]] = {}
    for info in segments:
        ranges = ranges_by_run.get(info.index, [])
        lines = [
            line
            for loaded, start_line, end_line in ranges
            for line in loaded.lines[start_line:end_line]
        ]
        configs[info.index] = parse_jvm_heap_config(lines)
        max_heap_from_log[info.index] = parse_max_heap_from_log(lines)
        environments[info.index] = parse_jvm_environment(lines)
        capacity, _ = resolve_max_heap(
            configs[info.index], max_heap_bytes, max_heap_from_log[info.index]
        )
        max_heap_by_run[info.index] = capacity
        info.max_heap_kb = capacity
        if all(event.wall_clock for event in events_by_run[info.index]):
            observed[info.index] = observed_wall_bounds(ranges, events_by_run[info.index])

    def summarize(
        window_events: list[GCEvent],
        candidate_runs: set[int],
        window_start: datetime | None,
        window_end: datetime | None,
    ) -> GCSummary:
        runs = {event.segment for event in window_events}
        if window_start or window_end:
            runs.update(
                run
                for run in candidate_runs
                if run in observed
                and (window_start is None or observed[run][1] > window_start)
                and (window_end is None or observed[run][0] < window_end)
            )
        single_run = next(iter(runs)) if len(runs) == 1 else None
        summary = build_comprehensive_summary(
            window_events,
            thresholds,
            gc_type=gc_type,
            jvm_heap_config=configs[single_run] if single_run is not None else None,
            max_heap_bytes=max_heap_bytes,
            max_heap_from_log_bytes=max_heap_from_log[single_run]
            if single_run is not None
            else None,
            max_heap_by_segment={run: max_heap_by_run[run] for run in runs},
            window_start=window_start,
            window_end=window_end,
            observed_bounds={run: observed[run] for run in runs if run in observed},
            side_records=[
                record
                for run in sorted(runs)
                for record in select_side_records(
                    ranges_by_run.get(run, []), events_by_run[run], run, window_start, window_end
                )
            ],
            environment=environments[single_run] if single_run is not None else None,
        )
        last_run = all_events[-1].segment
        summary.includes_log_tail = last_run in runs and (
            window_end is None or (last_run in observed and window_end >= observed[last_run][1])
        )
        return summary

    selected_runs = {event.segment for event in events}
    log_tz = next((e.timestamp.tzinfo for e in all_events if e.wall_clock), None)
    start_dt = parse_time_option(start, "--start", log_tz)
    end_dt = parse_time_option(end, "--end", log_tz)
    if start_dt is not None and end_dt is not None and end_dt <= start_dt:
        raise ValueError("--end must be later than --start")
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
        if (
            not events
            and not any(
                select_side_records(
                    ranges_by_run.get(run, []), events_by_run[run], run, start_dt, end_dt
                )
                for run in selected_runs
            )
            and not any(
                run in observed
                and start_dt
                and end_dt
                and observed[run][0] <= start_dt
                and observed[run][1] >= end_dt
                for run in selected_runs
            )
        ):
            raise ValueError(f"No GC pauses or other evidence in the {window_label}")
        if start_dt and end_dt:
            day = timedelta(days=1)
            previous = filter_window(
                [event for event in all_events if event.wall_clock], start_dt - day, end_dt - day
            )
            previous_start, previous_end = start_dt - day, end_dt - day
            if previous or any(
                first <= previous_start and last >= previous_end
                for first, last in observed.values()
            ):
                comparison = summarize(previous, set(observed), previous_start, previous_end)
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
        summary=summarize(events, selected_runs, start_dt, end_dt),
        window_label=window_label,
        comparison=comparison,
        comparison_label=comparison_label,
        file_coverages=file_coverages,
    )
