"""Report content: one list of sections rendered both to the terminal (Rich) and Markdown.

``build_sections`` decides *what* the report says; ``render_rich`` and
``markdown.render_markdown`` only decide how it looks, so both outputs always agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .analysis import (
    MIN_PAUSES_FOR_P99,
    cleaned_floors,
    describe_floor_step,
    describe_time_to_capacity,
    describe_trend_numbers,
    format_duration,
    format_mb_per_hour,
    format_time,
    window_name,
)
from .coverage import build_unparsed_warning
from .findings import build_diagnosis, build_findings, overall_status
from .models import (
    GC_KINDS,
    CandidateCoverage,
    FileCoverage,
    Finding,
    GCEvent,
    GCSummary,
    JVMHeapConfig,
    PauseClustering,
    PauseMoment,
    PauseShareWindow,
    SegmentInfo,
)

GC_ANALYZE_THEME = Theme(
    {
        "critical": "bold red",
        "warning": "bold yellow",
        "success": "bold green",
        "info": "cyan",
        "metric": "white",
        "label": "dim white",
        "header": "bold magenta",
    }
)
console = Console(theme=GC_ANALYZE_THEME)

type SectionKind = Literal["kv", "table", "text", "bullets", "findings"]
type Style = Literal["", "info", "warning", "critical", "success", "header"]


@dataclass
class Section:
    """One block of the report."""

    id: str
    title: str
    kind: SectionKind
    rows: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    headers: list[str] = field(default_factory=list[str])
    table_rows: list[list[str]] = field(default_factory=list[list[str]])
    # One number per table row for ranking rows without reading their display text
    # (the timeline: share of the slice the application was paused)
    row_weights: list[float] = field(default_factory=list[float])
    text: str = ""
    items: list[str] = field(default_factory=list[str])
    findings: list[Finding] = field(default_factory=list[Finding])
    style: Style = ""


@dataclass
class ReportContext:
    """Everything the report needs."""

    summary: GCSummary
    gc_type: str
    events: list[GCEvent]
    coverage: CandidateCoverage
    file_coverages: list[FileCoverage] = field(default_factory=list[FileCoverage])
    segments: list[SegmentInfo] = field(default_factory=list[SegmentInfo])
    segment_label: str = "single JVM run"
    window_label: str | None = None  # set when --start/--end narrowed the analysis
    comparison: GCSummary | None = None  # same window 24 h earlier
    comparison_label: str = ""
    inputs: list[str] = field(default_factory=list[str])
    # Built once (cli) so the report and the exit code use the same list; None = build here
    findings: list[Finding] | None = None


# ============================================================
# FORMATTING
# ============================================================


def format_seconds(seconds: float) -> str:
    """Seconds for display: '0.123s', '72.0s (1.2m)'."""
    if seconds > 60:
        return f"{seconds:.1f}s ({seconds / 60:.1f}m)"
    return f"{seconds:.3f}s"


def format_kb(kb: float) -> str:
    """KB as '512 MB' / '1.25 GB'."""
    mb = kb / 1024
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.0f} MB"


def event_time(event: GCEvent) -> str:
    """Display time of an event."""
    return format_time(event.timestamp, event.wall_clock, event.uptime_seconds)


def sanitize_text(text: str) -> str:
    """Strip emoji markers (Markdown output)."""
    for marker in ("⚠️ ", "⚠ ", "🔴 ", "🟠 ", "🟡 ", "🟢 ", "⚪ ", "✅ ", "✖ ", "✓ "):
        text = text.replace(marker, "")
    return text


# ============================================================
# ROW BUILDERS
# ============================================================


def build_parsing_coverage_rows(
    coverage: CandidateCoverage, usable_events: int, events_without_heap: int
) -> list[tuple[str, str]]:
    """What was read, parsed, folded into multi-line records, and not understood."""
    rows = [
        ("Total log lines", str(coverage.total_lines)),
        ("GC event lines found", str(coverage.candidate_lines)),
        ("GC event lines parsed", str(coverage.parsed_candidate_lines)),
        (
            "GC event lines NOT parsed",
            f"{coverage.unparsed_candidate_lines} ({coverage.unparsed_percentage:.1f}%)",
        ),
        ("Continuation lines (multi-line records)", str(coverage.continuation_lines)),
        ("Pause events", str(usable_events)),
        ("Pauses without heap sizes", str(events_without_heap)),
    ]
    if coverage.truncated_final_record:
        rows.append(("Unfinished final record (log ends here)", coverage.truncated_final_record))
    rows.extend(("Unparsed sample", sample) for sample in coverage.unparsed_samples)
    return rows


def build_file_coverage_table(files: list[FileCoverage]) -> tuple[list[str], list[list[str]]]:
    """Per-file coverage table."""
    headers = ["File", "Collector", "Lines", "GC lines", "Parsed", "Not parsed", "Events"]
    rows = [
        [
            f.path,
            f.gc_type,
            str(f.coverage.total_lines),
            str(f.coverage.candidate_lines),
            str(f.coverage.parsed_candidate_lines),
            f"{f.coverage.unparsed_candidate_lines} ({f.coverage.unparsed_percentage:.1f}%)",
            str(f.events),
        ]
        for f in files
    ]
    return headers, rows


def build_time_window_rows(
    first_timestamp: datetime,
    last_timestamp: datetime,
    first_uptime_seconds: float | None,
    last_uptime_seconds: float | None,
    wall_clock: bool = True,
) -> list[tuple[str, str]]:
    """First/last event times."""
    no_clock = "n/a (log has uptime only; pass --jvm-start)"

    def uptime(value: float | None) -> str:
        return f"{value:.3f}s" if value is not None else "n/a (no uptime in log)"

    return [
        (
            "First event timestamp",
            format_time(first_timestamp, True, None) if wall_clock else no_clock,
        ),
        (
            "Last event timestamp",
            format_time(last_timestamp, True, None) if wall_clock else no_clock,
        ),
        ("First event uptime", uptime(first_uptime_seconds)),
        ("Last event uptime", uptime(last_uptime_seconds)),
    ]


def _rate_or_count(count: int, per_hour: float | None, summary: GCSummary, digits: int = 2) -> str:
    if per_hour is not None:
        return f"{per_hour:.{digits}f} per hour ({count} total)"
    return f"{count} in {format_duration(summary.runtime_seconds)} (window too short for a rate)"


def _interpret_gc_overhead(summary: GCSummary) -> str:
    limits = summary.thresholds
    if summary.gc_overhead_pct > limits.gc_overhead_critical_percentage:
        return (
            f"over the {limits.gc_overhead_critical_percentage:g}% critical limit: the "
            "logged GC pause share is high"
        )
    if summary.gc_overhead_pct > limits.gc_overhead_warning_percentage:
        return f"over the {limits.gc_overhead_warning_percentage:g}% warning limit"
    return f"under the {limits.gc_overhead_warning_percentage:g}% warning limit"


def _interpret_p99_pause(summary: GCSummary) -> str:
    limits = summary.thresholds
    p99 = summary.worst_p99_seconds
    if p99 > limits.pause_critical_seconds:
        return f"over the {limits.pause_critical_seconds:g} s critical limit"
    if p99 > limits.pause_warning_seconds:
        return f"over the {limits.pause_warning_seconds:g} s warning limit"
    return f"within the {limits.pause_warning_seconds:g} s limit"


def describe_p99(summary: GCSummary) -> str:
    """P99 of the kind of pause with the worst one, or why a P99 is not shown."""
    if summary.worst_p99_count < MIN_PAUSES_FOR_P99:
        return (
            f"n/a (only {summary.total_event_count} pauses; a P99 needs about {MIN_PAUSES_FOR_P99})"
        )
    if summary.worst_p99_kind is None:
        return (
            f"{summary.worst_p99_seconds:.3f}s over all {summary.worst_p99_count} pauses "
            f"({_interpret_p99_pause(summary)})"
        )
    return (
        f"{summary.worst_p99_seconds:.3f}s for the {summary.worst_p99_count} "
        f"{summary.worst_p99_kind} pauses, the slowest kind with enough pauses for a P99 "
        f"({_interpret_p99_pause(summary)}); all pauses together {summary.overall_pauses.p99:.3f}s"
    )


def format_pause_share(window: PauseShareWindow) -> str:
    """'98.7% paused (4.9 min of 5 min) from 2026-01-07T10:04:55.428+02:00'."""
    return (
        f"{window.share_percentage:.1f}% paused ({format_duration(window.paused_seconds)} of "
        f"{window_name(window.window_seconds)}) from "
        f"{format_time(window.window_start, window.wall_clock, window.uptime_seconds)}"
    )


def _overhead_text(summary: GCSummary) -> str:
    if not summary.overhead_measured:
        return "n/a (single pause: no elapsed time to measure against)"
    if summary.requested_window_covered is False:
        return f"{summary.gc_overhead_pct:.2f}% (requested-window share unavailable)"
    return f"{summary.gc_overhead_pct:.2f}% ({_interpret_gc_overhead(summary)})"


def _fullest_cleaned_floor(summary: GCSummary) -> str | None:
    """Highest occupancy right after a collection that cleans the old generation."""
    trend = summary.floor_trend
    cleaned = cleaned_floors(trend)
    if not cleaned:
        return None
    fullest = max(cleaned, key=lambda f: f.pct_of_capacity or 0.0)
    what, of = "heap", "max heap"
    return (
        f"{format_kb(fullest.value_kb)} {what} ({fullest.pct_of_capacity:.1f}% of {of}) after "
        f"{fullest.source} at "
        f"{format_time(fullest.timestamp, fullest.wall_clock, fullest.uptime_seconds)}"
    )


def build_timeline_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """The window in equal slices: where the pauses, Full GCs and heap growth happened."""
    basis = (
        "run max heap"
        if len(summary.max_heap_by_segment) > 1
        else ("max heap" if summary.heap.max_heap_known else "committed heap")
    )
    headers = [
        "From",
        "Pauses",
        "Time paused",
        "Longest pause",
        "Full GCs",
        f"Heap after last GC (% of {basis})",
    ]
    rows: list[list[str]] = []
    for bucket in summary.timeline:
        if bucket.heap_after_kb is None:
            heap_text = "—"
        elif bucket.heap_after_percentage is None:
            heap_text = format_kb(bucket.heap_after_kb)
        else:
            heap_text = f"{format_kb(bucket.heap_after_kb)} ({bucket.heap_after_percentage:.1f}%)"
        pause_share = (
            f"{bucket.paused_percentage:.3f}% ({bucket.paused_seconds:.3f} s)"
            if 0 < bucket.paused_seconds < 1
            else f"{bucket.paused_percentage:.1f}% ({bucket.paused_seconds:.1f} s)"
        )
        rows.append(
            [
                format_time(bucket.start, bucket.wall_clock, bucket.uptime_seconds),
                str(bucket.pause_count),
                pause_share if bucket.paused_seconds else "—",
                format_seconds(bucket.longest_pause_seconds) if bucket.pause_count else "—",
                str(bucket.full_gc_count) if bucket.full_gc_count else "—",
                heap_text,
            ]
        )
    return headers, rows


def build_frequency_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """GC rates (only when the window is long enough) and Full GC timing."""
    rows = [
        (
            "Young GCs",
            _rate_or_count(summary.young_gc_count, summary.young_gc_per_hour, summary, 1),
        ),
        (
            "Heap-pressure Full GCs",
            _rate_or_count(summary.heap_full_gc_count, summary.full_gc_per_hour, summary),
        ),
    ]
    if summary.explicit_full_gc_count:
        rows.append(("Explicit Full GCs (System.gc() etc.)", str(summary.explicit_full_gc_count)))
    if summary.metadata_full_gc_count:
        rows.append(("Metaspace-triggered Full GCs", str(summary.metadata_full_gc_count)))
    if summary.avg_full_gc_interval_min is not None:
        rows.append(
            (
                "Avg time between heap Full GCs",
                format_duration(summary.avg_full_gc_interval_min * 60),
            )
        )
    if summary.min_full_gc_interval_min is not None:
        rows.append(
            (
                "Shortest gap between heap Full GCs",
                format_duration(summary.min_full_gc_interval_min * 60),
            )
        )
    if summary.time_to_first_full_gc_hours is not None:
        origin = (
            "after JVM start"
            if summary.time_to_first_full_gc_from_jvm_start
            else "after the first pause in the window"
        )
        rows.append(
            (
                "First heap Full GC",
                f"{format_duration(summary.time_to_first_full_gc_hours * 3600)} {origin}",
            )
        )
    if summary.max_full_gc_streak > 1:
        rows.append(
            (
                "Back-to-back heap Full GCs (next starts within 5 min of the first ending)",
                str(summary.max_full_gc_streak),
            )
        )
    return rows


def build_full_gc_cause_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Full GC counts by cause."""
    labels = {
        "heap": "heap pressure",
        "explicit": "explicit (excluded from rates)",
        "metadata": "metaspace",
        "other": "other known trigger",
        "unknown": "unknown",
    }
    headers = ["Cause", "Category", "Count", "Total pause", "Longest"]
    rows = [
        [
            c.cause,
            labels[c.category],
            str(c.count),
            format_seconds(c.total_pause_seconds),
            format_seconds(c.max_pause_seconds),
        ]
        for c in summary.full_gc_causes
    ]
    return headers, rows


def build_cause_rows(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Pause causes by kind (all kinds)."""
    headers = ["GC kind", "Cause", "Count"]
    rows: list[list[str]] = []
    for kind in GC_KINDS:
        for cause, count in summary.causes_by_kind.get(kind, {}).items():
            rows.append([kind, cause, str(count)])
    return headers, rows


def build_overhead_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Time in GC."""
    rows = [("Total time in GC pauses", f"{summary.total_gc_time_sec:.1f} seconds")]
    if summary.overhead_measured:
        rows.append((f"GC pause share ({summary.window_basis})", f"{summary.gc_overhead_pct:.2f}%"))
        rows.append(
            (
                f"Time outside logged GC pauses ({summary.window_basis})",
                f"{summary.throughput_pct:.2f}%",
            )
        )
    else:
        rows.append(("GC overhead", "n/a (single pause: no elapsed time to measure against)"))
    rows += [
        (f"Worst {window_name(w.window_seconds)}", format_pause_share(w))
        for w in summary.worst_pause_shares
    ]
    return rows


def build_heap_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Heap before/after GC against max heap."""
    heap = summary.heap
    if not heap.events_with_heap_data:
        return [("Heap data", "not in log")]
    if heap.exceeds_max_heap and len(summary.max_heap_by_segment) <= 1:
        return [
            ("Max heap", f"{format_kb(heap.max_heap_kb or 0)} (conflicts with logged occupancy)"),
            ("Peak before GC", format_kb(heap.peak_before_gc_kb)),
            ("Peak after GC", format_kb(heap.peak_after_gc_kb)),
        ]
    if len(summary.max_heap_by_segment) > 1:
        rows = [
            ("Max heap", "reported by JVM run"),
            ("Peak before GC across runs", format_kb(heap.peak_before_gc_kb)),
            ("Peak after GC across runs", format_kb(heap.peak_after_gc_kb)),
            ("Pauses with heap sizes", str(heap.events_with_heap_data)),
        ]
        for peak in summary.run_heap_peaks:
            usage = format_kb(peak.peak_after_gc_kb)
            if peak.fraction_of_max is not None and peak.max_heap_kb:
                usage += f" ({peak.fraction_of_max:.1%} of {format_kb(peak.max_heap_kb)} max)"
            rows.append((f"Run {peak.run} peak after GC", usage))
        return rows
    basis = "max heap" if heap.max_heap_known else "committed heap"
    max_text = format_kb(heap.max_heap_kb) if heap.max_heap_kb else "unknown"
    rows = [
        (
            "Max heap",
            f"{max_text} (from {heap.max_heap_source})"
            if heap.max_heap_known
            else f"unknown; occupancy percentages use peak observed committed heap ({max_text})",
        ),
        (
            "Peak before GC",
            f"{format_kb(heap.peak_before_gc_kb)} ({heap.peak_before_gc_pct:.1f}% of {basis})",
        ),
        (
            "Peak after GC (any Young/Mixed/Full; still includes old-gen garbage)",
            f"{format_kb(heap.peak_after_gc_kb)} ({heap.peak_after_gc_pct:.1f}% of {basis})",
        ),
        (
            "Average after GC (Young/Mixed/Full)",
            f"{format_kb(heap.avg_after_gc_kb)} ({heap.avg_after_gc_pct:.1f}% of {basis})",
        ),
    ]
    if heap.max_heap_known and not heap.exceeds_max_heap:
        rows.append(("Headroom above peak after GC", f"{heap.headroom_pct:.1f}% of max heap"))
    if fullest := _fullest_cleaned_floor(summary):
        rows.append(("Highest post-Full-GC occupancy", fullest))
    rows.append(("Pauses with heap sizes", str(heap.events_with_heap_data)))
    return rows


def build_pause_distribution_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Pause distribution by kind."""
    headers = [
        "GC Type",
        "Count",
        "Total (full durations)",
        "Average",
        "Median",
        "P95",
        "P99",
        "Maximum",
    ]

    def row(label: str, stats_key: str | None) -> list[str]:
        stats = summary.overall_pauses if stats_key is None else summary.pauses_by_kind[stats_key]
        return [
            label,
            str(stats.count),
            format_seconds(stats.total),
            format_seconds(stats.average),
            format_seconds(stats.median),
            format_seconds(stats.p95),
            format_seconds(stats.p99) if stats.count >= MIN_PAUSES_FOR_P99 else "n/a",
            format_seconds(stats.maximum),
        ]

    rows = [row("All pauses", None)]
    rows += [row(kind, kind) for kind in GC_KINDS if kind in summary.pauses_by_kind]
    return headers, rows


def build_pause_violation_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Counts of long pauses."""
    rows: list[tuple[str, str]] = []
    for label, count in (
        ("Pauses > 1s", summary.pauses_over_1s),
        ("Pauses > 5s", summary.pauses_over_5s),
        ("Pauses > 30s", summary.pauses_over_30s),
        ("Pauses > 60s", summary.pauses_over_60s),
    ):
        if count:
            rows.append((label, str(count)))
    return rows


def pause_moment_text(moment: PauseMoment) -> str:
    """Display time of a pause."""
    return format_time(moment.timestamp, moment.wall_clock, moment.uptime_seconds)


def build_top_pauses_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Longest pauses with time, kind, cause and heap (``GCSummary.top_pauses``)."""
    time_header = {
        "end": "Time (pause end)",
        "start": "Time (pause start)",
    }.get(summary.pause_stamps or "", "Time (as logged)")
    headers = [
        time_header,
        "Pause",
        "Kind (cause)",
        "Heap before → after",
        f"{'Old-region footprint' if summary.is_g1 else 'Old gen after'} "
        f"(% of {summary.old_pct_basis})",
    ]
    if summary.cpu_times_logged:
        headers.append("CPU user / sys / real (s)")
    rows: list[list[str]] = []
    for pause in summary.top_pauses:
        heap_text = (
            f"{format_kb(pause.heap_before_kb)} → {format_kb(pause.heap_after_kb)} "
            f"of {format_kb(pause.heap_total_kb)}"
            if pause.has_heap_data
            else "—"
        )
        old_text = (
            f"{pause.old_pct:.1f}%"
            if pause.old_pct is not None
            else (format_kb(pause.old_after_kb) if pause.old_after_kb is not None else "—")
        )
        row = [
            pause_moment_text(pause.at),
            format_seconds(pause.pause_seconds),
            pause.description,
            heap_text,
            old_text,
        ]
        if summary.cpu_times_logged:
            row.append(
                f"{pause.cpu_user_seconds:.2f} / {pause.cpu_sys_seconds:.2f} / "
                f"{pause.cpu_real_seconds:.2f}"
                if pause.cpu_user_seconds is not None
                and pause.cpu_sys_seconds is not None
                and pause.cpu_real_seconds is not None
                else "—"
            )
        rows.append(row)
    return headers, rows


def build_floor_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Old-gen floor trend headline."""
    trend = summary.floor_trend
    rows = [("Measurement used for trend", trend.measurement or "none available")]
    if trend.latest_run_only:
        rows.append(("JVM runs", "the latest run only; earlier runs had a different heap"))
    if trend.capacity_kb:
        rows.append(
            ("Capacity used for %", f"{format_kb(trend.capacity_kb)} ({trend.capacity_source})")
        )
    used = trend.trend_floors
    skipped = len(trend.floors) - len(used)
    rows.append(
        (
            "Floors",
            f"{len(used)} comparable after warm-up, {skipped} other samples shown below"
            if skipped
            else str(len(used)),
        )
    )
    if used:
        rows.append(
            (
                "First → last floor",
                f"{format_kb(used[0].value_kb)} → {format_kb(used[-1].value_kb)}",
            )
        )
    if trend.step_change is not None:
        rows.append(("⚠ Step change", describe_floor_step(trend)))
    if trend.assessed and trend.slope_mb_per_hour is not None and trend.p_value is not None:
        pct = (
            f" ({trend.slope_pct_per_hour:+.2f}% of capacity/h)"
            if trend.slope_pct_per_hour is not None
            else ""
        )
        rows.append(("Slope (Theil-Sen)", f"{format_mb_per_hour(trend.slope_mb_per_hour)}{pct}"))
        if trend.slope_low_mb_per_hour is not None and trend.slope_high_mb_per_hour is not None:
            rows.append(
                (
                    "Slope, 90% interval",
                    f"{format_mb_per_hour(trend.slope_low_mb_per_hour)} to "
                    f"{format_mb_per_hour(trend.slope_high_mb_per_hour)}",
                )
            )
        growth = f"{trend.growth_mb or 0.0:+.0f} MB"
        if trend.growth_pct_of_capacity is not None:
            growth += f" ({trend.growth_pct_of_capacity:+.1f}% of capacity)"
        rows.append(("Growth over the span", f"{growth} in {trend.span_hours:.1f} h"))
        p_text = "< 0.001" if trend.p_value < 0.001 else f"{trend.p_value:.3f}"
        sampled = (
            f" on {trend.trend_sample_size} evenly spaced floors"
            if trend.trend_sample_size < len(used)
            else ""
        )
        rows.append(("Trend test (Mann-Kendall p)", f"{p_text}{sampled}"))
        verdicts = {
            "growing": "growing: the trend is consistent and large enough to matter",
            "stable": "no material growth",
            "unclear": "no consistent trend: the floors moved, but not steadily",
        }
        rows.append(("Verdict", verdicts[trend.direction or "stable"]))
        if to_capacity := describe_time_to_capacity(trend):
            rows.append(("Projection", to_capacity))
    else:
        rows.append(("Trend", f"not assessed: {trend.reason}"))
    return rows


def build_floor_table(summary: GCSummary, limit: int = 30) -> tuple[list[str], list[list[str]]]:
    """Individual floors so the reader can see the trend themselves.

    CMS samples measure the old generation and the others the whole heap, so each row names
    what it measured and what its percentage is of.
    """
    headers = ["Time", "After", "Occupancy", "Share"]
    floors = summary.floor_trend.floors
    if len(floors) > limit:  # keep first, last and an even spread
        step = (len(floors) - 1) / (limit - 1)
        floors = [floors[round(i * step)] for i in range(limit)]
    rows: list[list[str]] = []
    for f in floors:
        old_gen = f.measurement.startswith("old-generation")
        rows.append(
            [
                format_time(f.timestamp, f.wall_clock, f.uptime_seconds),
                f"{f.source} (start-up, not in trend)" if f.warmup else f.source,
                f"{format_kb(f.value_kb)} {'old gen' if old_gen else 'heap'}",
                f"{f.pct_of_capacity:.1f}% of {'old generation' if old_gen else 'max heap'}"
                if f.pct_of_capacity is not None
                else "—",
            ]
        )
    return headers, rows


def build_old_gen_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Old-gen occupancy (sawtooth) and Full GC effectiveness."""
    rows: list[tuple[str, str]] = []
    basis = summary.old_pct_basis
    label = "old-region footprint" if summary.is_g1 else "old-generation occupancy"
    if summary.peak_old_pct is not None and summary.avg_old_pct is not None:
        rows.append((f"Peak {label} after any pause", f"{summary.peak_old_pct:.1f}% of {basis}"))
        rows.append((f"Average {label} after any pause", f"{summary.avg_old_pct:.1f}% of {basis}"))
    if summary.full_gc_count:
        reclaimed = format_kb(summary.avg_reclaimed_kb)
        if summary.avg_full_gc_reclaimed_pct is not None:
            reclaimed += f" ({summary.avg_full_gc_reclaimed_pct:.1f}% of the heap before it)"
        rows.append(("Avg heap freed per Full GC", reclaimed))
        rows.append(
            ("Full GCs that freed heap", f"{summary.full_gc_reducing}/{summary.full_gc_count}")
        )
        if summary.heap_full_gc_reclaimed_pcts:
            shown = summary.heap_full_gc_reclaimed_pcts[-12:]
            earlier = len(summary.heap_full_gc_reclaimed_pcts) - len(shown)
            rows.append(
                (
                    "Heap freed by each heap-pressure Full GC, in time order",
                    (f"(first {earlier} omitted) " if earlier else "")
                    + ", ".join(f"{pct:.1f}%" for pct in shown),
                )
            )
        if summary.ineffective_full_gc_count:
            rows.append(
                (
                    "Heap-pressure Full GCs with low reclaim and high remaining occupancy",
                    f"{summary.ineffective_full_gc_count}/{summary.heap_full_gc_count}",
                )
            )
        if summary.avg_post_full_gc_pct is not None:
            rows.append(
                (
                    f"Average {label} after Full GC",
                    f"{summary.avg_post_full_gc_pct:.1f}% of {basis}",
                )
            )
        if summary.reclamation_declining:
            rows.append(("⚠ Reclamation declining over time", "yes"))
    return rows


def build_trend_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Early / middle / late thirds of the window."""
    measure = "old-region footprint" if summary.is_g1 else "old-generation occupancy"
    headers = [
        "Period",
        f"Average {measure} after a pause (% of {summary.old_pct_basis})",
        "Full GCs",
    ]
    rows: list[list[str]] = []
    for name in ("early", "middle", "late"):
        if period := summary.period_stats.get(name):
            avg = period.average_old_gen_percentage
            rows.append(
                [name, f"{avg:.1f}%" if avg is not None else "—", str(period.full_gc_count)]
            )
    return headers, rows


def build_allocation_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Allocation between GCs and promotion."""
    rows: list[tuple[str, str]] = []
    if summary.allocation_rate_mb_sec is not None:
        rows.append(
            (
                "Allocation rate (between GCs, while the application runs)",
                f"{summary.allocation_rate_mb_sec:.2f} MB/s ({summary.allocation_basis})",
            )
        )
    if summary.total_promoted_kb:
        rows.append(("Average promotion per young GC", format_kb(summary.avg_promotion_kb)))
        promoted = format_kb(summary.total_promoted_kb)
        if summary.promotion_rate_mb_sec is not None:
            promoted += f" ({summary.promotion_rate_mb_sec:.2f} MB/s)"
        rows.append(("Promoted to old gen by young GCs, total", promoted))
    return rows


def build_environment_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """JVM version and host facts from the log header."""
    env = summary.environment
    if not env:
        return []
    rows: list[tuple[str, str]] = []
    if env.jvm_version:
        rows.append(("JVM", env.jvm_version))
    if env.cpus_total is not None:
        rows.append(("CPUs", f"{env.cpus_total} total, {env.cpus_available} available to the JVM"))
    if env.physical_memory_kb:
        memory = format_kb(env.physical_memory_kb)
        if env.free_memory_kb is not None:
            memory += f" ({format_kb(env.free_memory_kb)} free at JVM start)"
        rows.append(("Physical memory", memory))
        heap = summary.heap
        if heap.max_heap_known and heap.max_heap_kb:
            share = heap.max_heap_kb / env.physical_memory_kb * 100
            rows.append(("Max heap as share of physical memory", f"{share:.0f}%"))
    if env.swap_total_kb is not None and env.swap_free_kb is not None:
        rows.append(
            (
                "Swap",
                f"{format_kb(env.swap_total_kb)} ({format_kb(env.swap_free_kb)} free at JVM start)"
                if env.swap_total_kb
                else "none configured",
            )
        )
    if env.large_pages:
        rows.append(("Large pages", env.large_pages))
    if env.pre_touch:
        rows.append(("Pre-touch", env.pre_touch))
    return rows


def build_cpu_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Where pause time went: user (collecting), sys (kernel), or waiting."""
    cpu = summary.cpu_stats
    if not cpu:
        return []
    rows = [
        ("Pauses with CPU times", str(cpu.pauses_with_cpu_times)),
        ("Pauses judged (real ≥ 0.1 s)", str(cpu.judged_pauses)),
        ("High kernel time (sys > 20% of user)", str(cpu.high_sys_count)),
    ]
    if cpu.worst_high_sys:
        rows.append(("Worst kernel time", cpu.worst_high_sys))
    rows.append(("Waiting, not working (real > 1.5 x user+sys)", str(cpu.off_cpu_count)))
    if cpu.worst_off_cpu:
        rows.append(("Worst wait", cpu.worst_off_cpu))
    if cpu.parallelism_by_kind:
        threads = summary.jvm_heap_config.parallel_gc_threads if summary.jvm_heap_config else None
        rows.append(
            (
                "CPU used per second of pause, median ((user+sys) ÷ real)",
                ", ".join(
                    f"{kind} {cpu.parallelism_by_kind[kind]:.1f}x"
                    for kind in GC_KINDS
                    if kind in cpu.parallelism_by_kind
                )
                + (f" (configured parallel GC workers: {threads})" if threads else ""),
            )
        )
    return rows


def build_concurrent_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Collector work done alongside the application."""
    stats = summary.concurrent_stats
    if not stats:
        return []
    share = (
        f" ({stats.share_percentage:.1f}% of the window)"
        if stats.share_percentage is not None
        else ""
    )
    rows = [
        ("Measured", stats.label),
        ("Count", str(stats.cycles)),
        ("Total time", f"{format_duration(stats.total_seconds)}{share}"),
        (
            "Average / longest",
            f"{format_duration(stats.average_seconds)} / {format_duration(stats.longest_seconds)}",
        ),
    ]
    if stats.cycles > 1 and summary.runtime_seconds:
        # an average only describes cycles that are spread over the window
        clustered = (
            stats.span_seconds is not None
            and stats.span_seconds < CLUSTERED_SHARE_OF_WINDOW * summary.runtime_seconds
        )
        if clustered and stats.span_seconds is not None:
            rows.append(
                (
                    "When",
                    f"all within {format_duration(stats.span_seconds)} ({stats.first_when} to "
                    f"{stats.last_when}) of a {format_duration(summary.runtime_seconds)} window",
                )
            )
        else:
            rows.append(("One every", format_duration(summary.runtime_seconds / stats.cycles)))
    rows.append(("Note", "runs on GC threads while the application runs; not in pause overhead"))
    return rows


def build_safepoint_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Logged safepoint phases and classification."""
    stats = summary.safepoint_stats
    if not stats:
        return []
    rows = [
        ("Safepoints logged", str(stats.count)),
        ("Total elapsed safepoint time", format_seconds(stats.total_stopped_seconds)),
        (
            "Longest elapsed safepoint",
            f"{format_seconds(stats.longest_stopped_seconds)} at {stats.longest_stopped_when}",
        ),
    ]
    for label, duration in (
        ("Time reaching safepoints (where logged)", stats.total_reaching_seconds),
        ("Time at safepoints (where logged)", stats.total_at_safepoint_seconds),
    ):
        rows.append((label, format_seconds(duration) if duration is not None else "n/a"))
    if stats.longest_stopping_seconds:
        rows.append(
            (
                "Longest time reaching safepoint",
                f"{format_seconds(stats.longest_stopping_seconds)} at "
                f"{stats.longest_stopping_when}",
            )
        )
    rows.extend(
        [
            ("Safepoints taking ≥ 1 s to reach", str(stats.slow_to_stop_count)),
            ("Associated with GC", str(stats.gc_count)),
            ("Known non-GC operations", str(stats.non_gc_count or 0)),
            ("Unmatched or unknown operations", str(stats.unmatched_count)),
        ]
    )
    if stats.non_gc_count:
        rows.append(
            (
                "Longest known non-GC safepoint",
                f"{format_seconds(stats.longest_non_gc_seconds)} elapsed at "
                f"{stats.longest_non_gc_when} ({stats.longest_non_gc_operation})",
            )
        )
    return rows


def build_g1_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """G1 metrics."""
    g1 = summary.g1_metrics
    if not g1:
        return []
    per_hour = (
        f"{g1.mixed_gc_frequency_per_hour:.2f}"
        if g1.mixed_gc_frequency_per_hour is not None
        else "n/a (short window)"
    )
    rows = [
        ("Mixed GC count", str(g1.mixed_gc_count)),
        ("Mixed GCs per hour", per_hour),
        ("Concurrent marking cycles", str(g1.concurrent_marking_cycles)),
    ]
    if g1.marking_cycles_per_hour is not None and g1.concurrent_marking_cycles:
        rows.append(("Marking cycles per hour", f"{g1.marking_cycles_per_hour:.2f}"))
    if g1.median_marking_start_pct is not None:
        rows.append(
            (
                "Old gen when marking starts (median)",
                f"{g1.median_marking_start_pct:.1f}% of {summary.old_pct_basis}",
            )
        )
    if g1.concurrent_start_count:
        rows.append(
            (
                'Marking cycles started with cause "G1 Humongous Allocation"',
                f"{g1.humongous_concurrent_start_count} of {g1.concurrent_start_count} (the "
                "cause names when the threshold was noticed, not why it was exceeded)",
            )
        )
    rows.append(('Pauses with cause "G1 Humongous Allocation"', str(g1.humongous_allocation_count)))
    if g1.typical_humongous_kb is not None:
        typical = format_kb(g1.typical_humongous_kb)
        if g1.typical_humongous_pct is not None:
            typical += f" ({g1.typical_humongous_pct:.1f}% of {summary.old_pct_basis})"
        rows.append(("Humongous region footprint, median before a pause", typical))
    if g1.peak_humongous_kb is not None:
        peak = format_kb(g1.peak_humongous_kb)
        if g1.peak_humongous_pct is not None:
            peak += f" ({g1.peak_humongous_pct:.1f}% of {summary.old_pct_basis})"
        rows.append(("Humongous region footprint, peak", peak))
    if g1.humongous_allocation_mb_sec is not None:
        share = (
            f" ({g1.humongous_allocation_share_pct:.1f}% of all allocation)"
            if g1.humongous_allocation_share_pct is not None
            else ""
        )
        rows.append(
            ("Humongous allocation rate", f"{g1.humongous_allocation_mb_sec:.2f} MB/s{share}")
        )
    rows += [
        ("Evacuation failures", str(g1.evacuation_failure_count)),
        ("To-space exhausted", str(g1.to_space_exhausted_count)),
    ]
    if g1.mmu_violation_count:
        rows.append(
            (
                "Pause-time goal missed (MMU target violated lines)",
                str(g1.mmu_violation_count),
            )
        )
    return rows


def build_cms_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """CMS metrics."""
    cms = summary.cms_metrics
    if not cms:
        return []
    per_hour = (
        f"{cms.cms_cycle_frequency_per_hour:.2f}"
        if cms.cms_cycle_frequency_per_hour is not None
        else "n/a (short window)"
    )
    rows = [
        ("Concurrent cycles (Initial Marks)", str(cms.concurrent_cycles)),
        ("CMS cycles per hour", per_hour),
        ("Average Initial Mark pause", format_seconds(cms.average_initial_mark_pause_seconds)),
        ("Average Remark pause", format_seconds(cms.average_remark_pause_seconds)),
        ("Concurrent mode failures", str(cms.concurrent_mode_failures)),
        ("Promotion failures", str(summary.promotion_failure_count)),
    ]
    if cms.concurrent_mode_failures:
        rows.append(("⚠ Old gen filled before the concurrent cycle finished", ""))
    return rows


def build_metaspace_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Metaspace usage and metaspace-triggered Full GCs."""
    meta = summary.metaspace_analysis
    if not meta:
        return []
    rows: list[tuple[str, str]] = []
    if meta.metaspace_events_count:
        rows.append(
            (
                "Metaspace used (first → peak → last)",
                f"{format_kb(meta.first_used_kb)} → {format_kb(meta.peak_used_kb)} → "
                f"{format_kb(meta.last_used_kb)}",
            )
        )
        if meta.limit_known and meta.max_metaspace_kb:
            rows.append(
                (
                    "Peak as % of -XX:MaxMetaspaceSize",
                    f"{meta.peak_metaspace_used_percentage:.1f}% of "
                    f"{format_kb(meta.max_metaspace_kb)}",
                )
            )
        else:
            rows.append(("Limit (-XX:MaxMetaspaceSize)", "not set in the log: no % shown"))
        rows.append(
            (
                "Growth after warm-up",
                f"{meta.metaspace_growth_kb / 1024:+.0f} MB"
                if meta.growth_measured
                else "n/a (no samples after warm-up)",
            )
        )
    if meta.metadata_full_gc_count:
        rows.append(("Full GCs triggered by metaspace", str(meta.metadata_full_gc_count)))
    return rows


def build_segment_table(segments: list[SegmentInfo]) -> tuple[list[str], list[list[str]]]:
    """JVM runs found in the input."""
    headers = ["Segment", "First event", "Last event", "Pauses", "Max heap", "Files"]
    rows = [
        [
            str(s.index),
            format_time(s.first_timestamp, s.wall_clock, s.first_uptime_seconds),
            format_time(s.last_timestamp, s.wall_clock, s.last_uptime_seconds),
            str(s.events),
            format_kb(s.max_heap_kb) if s.max_heap_kb else "unknown",
            ", ".join(s.files),
        ]
        for s in segments
    ]
    return headers, rows


def build_comparison_table(
    current: GCSummary, previous: GCSummary
) -> tuple[list[str], list[list[str]]]:
    """Incident window vs. the same window a day earlier."""
    headers = ["Metric", "This window", "Same window, previous day"]

    def heap_after(s: GCSummary) -> str:
        if not s.heap.events_with_heap_data:
            return "—"
        used = format_kb(s.heap.peak_after_gc_kb)
        return (
            f"{used} ({s.heap.peak_after_gc_pct:.1f}% of max heap)"
            if s.heap.max_heap_known and not s.heap.exceeds_max_heap
            else used
        )

    rows = [
        ["Pauses", str(current.total_event_count), str(previous.total_event_count)],
        [
            "Time in GC",
            format_seconds(current.total_gc_time_sec),
            format_seconds(previous.total_gc_time_sec),
        ],
        [
            "Time basis",
            f"{format_duration(current.runtime_seconds)} ({current.window_basis})",
            f"{format_duration(previous.runtime_seconds)} ({previous.window_basis})",
        ],
        [
            "GC pause share",
            f"{current.gc_overhead_pct:.2f}%" if current.overhead_measured else "n/a",
            f"{previous.gc_overhead_pct:.2f}%" if previous.overhead_measured else "n/a",
        ],
        [
            "P99 pause",
            describe_p99(current),
            describe_p99(previous),
        ],
        [
            "Longest pause",
            format_seconds(current.overall_pauses.maximum),
            format_seconds(previous.overall_pauses.maximum),
        ],
        [
            "Full GCs (heap / all)",
            f"{current.heap_full_gc_count} / {current.full_gc_count}",
            f"{previous.heap_full_gc_count} / {previous.full_gc_count}",
        ],
        ["Peak heap after GC", heap_after(current), heap_after(previous)],
    ]
    return headers, rows


# ============================================================
# NARRATIVE BLOCKS
# ============================================================


def describe_floor_trend(summary: GCSummary) -> str:
    """One sentence on the comparable occupancy samples."""
    trend = summary.floor_trend
    floors = trend.trend_floors
    if not floors:
        return f"Post-GC occupancy trend not assessed: {trend.reason}."
    what = trend.measurement.capitalize()
    first_last = f"{format_kb(floors[0].value_kb)} → {format_kb(floors[-1].value_kb)}"
    step = f" {describe_floor_step(trend)}." if trend.step_change is not None else ""
    if not trend.assessed or trend.slope_mb_per_hour is None:
        return (
            f"{what} {first_last} across {len(floors)} sample(s). Trend not "
            f"assessed: {trend.reason}.{step}"
        )
    direction = {
        "growing": "growing",
        "stable": "no material growth",
        "unclear": "no consistent trend",
    }[trend.direction or "stable"]
    projection = describe_time_to_capacity(trend)
    return (
        f"{what} {first_last} across {len(floors)} samples. {direction}, "
        f"{describe_trend_numbers(trend)}.{step}"
        + (f" {projection[0].upper()}{projection[1:]}." if projection else "")
    )


# Concurrent cycles packed into less than this share of the window are not "one every N"
CLUSTERED_SHARE_OF_WINDOW = 0.25


def describe_pause_clustering(clustering: PauseClustering | None) -> str:
    """Whether the longest pauses happen together, in words ("" when not judged)."""
    if clustering is None:
        return ""
    if clustering.clustered_count < 3 or clustering.first is None or clustering.last is None:
        return (
            f"The {clustering.longest_count} longest pauses are spread across the window "
            f"(no 3 within {clustering.window_seconds / 60:.0f} min)."
        )
    return (
        f"{clustering.clustered_count} of the {clustering.longest_count} longest pauses fall "
        f"within {format_duration(clustering.span_seconds)} "
        f"({pause_moment_text(clustering.first)} to {pause_moment_text(clustering.last)})."
    )


LEAK_VERDICT_TEXT = {
    "growing": "comparable post-GC occupancy is rising",
    "step_change": "post-GC occupancy shows a step increase",
    "full": "high post-Full-GC occupancy",
    "none": "no material increase in comparable post-GC occupancy",
    "not_assessed": "not assessed",
}


def describe_leak_risk(summary: GCSummary) -> str:
    """The leak verdict in words, with its one-line reason."""
    leak = summary.leak
    text = LEAK_VERDICT_TEXT[leak.verdict]
    if leak.verdict == "not_assessed" and leak.basis == "upper bound":
        return f"{text} (only an upper bound on retained heap is available)"
    if leak.verdict == "not_assessed":
        reason = summary.floor_trend.reason
        if summary.floor_trend.assessed:
            reason = "the floors moved, but not steadily enough to call it a trend"
        return f"{text} ({reason})" if reason else text
    return text


def describe_data_quality(coverage: CandidateCoverage) -> str:
    """Report parse coverage for recognized candidates across the supplied files."""
    text = (
        f"parsed {coverage.parsed_candidate_lines} of {coverage.candidate_lines} "
        "recognized pause candidates across the supplied files"
    )
    if coverage.truncated_final_record:
        text += ". The final file has an unfinished record"
    return text


def build_summary_rows(ctx: ReportContext) -> list[tuple[str, str]]:
    """The one summary of the run: status, window, pauses, heap, live set, data quality."""
    summary = ctx.summary
    heap = summary.heap
    basis = "max heap" if heap.max_heap_known else "committed heap"
    rows: list[tuple[str, str]] = [
        ("Status", determine_overall_status(report_findings(ctx))[0]),
        ("Retention assessment", describe_leak_risk(summary)),
    ]
    if ctx.events:
        first = min(ctx.events, key=lambda e: e.pause_start)
        last = max(ctx.events, key=lambda e: e.pause_end)
        # with --start/--end the requested bounds are the window, not the first/last pause;
        # otherwise it runs from the start of the first pause to the end of the last one
        span = (
            ctx.window_label.removeprefix("window ")
            if ctx.window_label
            else f"{format_time(first.pause_start, first.wall_clock, _start_uptime(first))} to "
            f"{format_time(last.pause_end, last.wall_clock, _end_uptime(last))}"
        )
        rows.append(("Window", span))
        rows.append(
            ("Time basis", f"{format_duration(summary.runtime_seconds)} of {summary.window_basis}")
        )
    elif ctx.window_label:
        rows.append(("Window", ctx.window_label.removeprefix("window ")))
        rows.append(
            ("Time basis", f"{format_duration(summary.runtime_seconds)} of {summary.window_basis}")
        )
    if summary.requested_window_covered is False:
        if summary.evidence_start is not None and summary.evidence_end is not None:
            rows.append(
                (
                    "Observed bounds",
                    f"{summary.evidence_start.isoformat()} to {summary.evidence_end.isoformat()}",
                )
            )
        rows.append(
            ("Window coverage", "The supplied records do not establish the full requested interval")
        )
    kinds = ", ".join(
        f"{summary.counts_by_kind[kind]} {kind}"
        for kind in GC_KINDS
        if kind in summary.counts_by_kind
    )
    rows.append(("Pauses", f"{summary.total_event_count} ({kinds})"))
    rows.append(
        (
            "Time in GC pauses",
            f"{format_seconds(summary.total_gc_time_sec)}. "
            f"Pause share of the {summary.window_basis} {_overhead_text(summary)}",
        )
    )
    worst = next((w for w in summary.worst_pause_shares if w.window_seconds == 300.0), None)
    if worst is not None:
        rows.append(("Worst 5 minutes", format_pause_share(worst)))
    rows.append(("P99 pause (full event durations)", describe_p99(summary)))
    if ctx.events:
        rows.append(
            (
                "Longest pause",
                f"{format_seconds(summary.overall_pauses.maximum)} ({summary.longest_pause_kind}, "
                f"{summary.longest_pause_cause}) at {summary.longest_pause_when}",
            )
        )
    if clustering := describe_pause_clustering(summary.pause_clustering):
        rows.append(("Longest pauses", clustering))
    rows.append(
        (
            "Heap after GC (peak, any Young/Mixed/Full)",
            (
                f"{format_kb(heap.peak_after_gc_kb)} ({heap.peak_after_gc_pct:.1f}% of {basis})"
                if heap.max_heap_known and not heap.exceeds_max_heap
                else format_kb(heap.peak_after_gc_kb)
            )
            if heap.events_with_heap_data
            else "n/a",
        )
    )
    rows.append(
        (
            "Highest post-Full-GC occupancy",
            _fullest_cleaned_floor(summary) or "n/a (comparable occupancy and max heap needed)",
        )
    )
    if summary.full_gc_causes:
        causes = ", ".join(f"{c.count} {c.cause}" for c in summary.full_gc_causes)
        rows.append(("Full GCs", f"{summary.full_gc_count} ({causes})"))
        rows.append(
            (
                "Of which heap-pressure",
                _rate_or_count(summary.heap_full_gc_count, summary.full_gc_per_hour, summary),
            )
        )
    else:
        rows.append(("Full GCs", "none"))
    rows.append(("Post-GC occupancy trend", describe_floor_trend(summary)))
    rows.append(("Parse coverage", describe_data_quality(ctx.coverage)))
    gaps: list[str] = []
    if summary.safepoint_stats is None:
        gaps.append("safepoint timing unavailable")
    if summary.cpu_stats is None:
        gaps.append("GC CPU timing unavailable")
    if not summary.heap.max_heap_known:
        gaps.append(
            "heap limits are reported by JVM run"
            if len(summary.max_heap_by_segment) > 1
            else "max heap unavailable"
        )
    elif summary.heap.exceeds_max_heap:
        gaps.append("heap limit conflicts with observed occupancy")
    if inconsistent := summary.events_with_inconsistent_data:
        gaps.append(
            f"{inconsistent} pause{'s' if inconsistent != 1 else ''} with impossible sizes "
            "(left out of heap figures)"
        )
    if gaps:
        rows.append(("Data limits", ", ".join(gaps)))
    return rows


def _start_uptime(event: GCEvent) -> float | None:
    if event.uptime_seconds is None:
        return None
    return event.uptime_seconds - (event.pause_time_seconds if event.stamp_at_pause_end else 0.0)


def _end_uptime(event: GCEvent) -> float | None:
    if event.uptime_seconds is None:
        return None
    return event.uptime_seconds + (0.0 if event.stamp_at_pause_end else event.pause_time_seconds)


def report_findings(ctx: ReportContext) -> list[Finding]:
    """The findings of this report, built once and kept on the context."""
    if ctx.findings is None:
        ctx.findings = build_findings(ctx.summary, ctx.gc_type, ctx.events, ctx.coverage)
    return ctx.findings


def determine_overall_status(findings: list[Finding]) -> tuple[str, Style]:
    """Overall status text and style: the worst severity among the findings."""
    status = overall_status(findings)
    if status == "critical":
        return "✖ CRITICAL - ACTION REQUIRED", "critical"
    if status == "warning":
        return "⚠ DEGRADED - INVESTIGATE", "warning"
    return "✓ No warnings among assessed JVM signals", "success"


# ============================================================
# SECTIONS
# ============================================================


def _kv(sid: str, title: str, rows: list[tuple[str, str]]) -> Section:
    return Section(id=sid, title=title, kind="kv", rows=rows)


def _table(sid: str, title: str, table: tuple[list[str], list[list[str]]]) -> Section:
    return Section(id=sid, title=title, kind="table", headers=table[0], table_rows=table[1])


def build_sections(ctx: ReportContext) -> list[Section]:
    """Whole report, in order."""
    s = ctx.summary
    out: list[Section] = []
    subtitle = [ctx.gc_type]
    if len(ctx.segments) > 1 or ctx.segment_label != "single JVM run":
        subtitle.append(ctx.segment_label)
    if ctx.window_label:
        subtitle.append(ctx.window_label)
    out.append(
        Section(
            id="header", title="GC Type", kind="text", text=" · ".join(subtitle), style="header"
        )
    )

    if warning := build_unparsed_warning(ctx.coverage):
        out.append(
            Section(
                id="unparsed", title="Incomplete Parse", kind="text", text=warning, style="warning"
            )
        )

    # 1. What is wrong, ranked, with evidence and action
    findings = report_findings(ctx)
    status_style = determine_overall_status(findings)[1]
    if diagnosis := build_diagnosis(s, findings, ctx.coverage):
        out.append(
            Section(
                id="diagnosis", title="Diagnosis", kind="text", text=diagnosis, style=status_style
            )
        )
    out.append(
        Section(
            id="findings",
            title="Findings",
            kind="findings",
            findings=findings,
            text="No warnings among assessed JVM signals.",
            style=status_style,
        )
    )
    # 2. The run in one block
    out.append(
        Section(
            id="summary",
            title="Summary",
            kind="kv",
            rows=build_summary_rows(ctx),
            style=status_style,
        )
    )
    # 3. When it happened
    if s.timeline:
        timeline = _table(
            "timeline",
            f"Timeline ({window_name(s.timeline_bucket_seconds)} slices)",
            build_timeline_table(s),
        )
        timeline.row_weights = [bucket.paused_percentage for bucket in s.timeline]
        out.append(timeline)
    if ctx.comparison is not None:
        out.append(
            _table(
                "comparison",
                f"Compared with {ctx.comparison_label}",
                build_comparison_table(s, ctx.comparison),
            )
        )

    # 4. How far the data can be trusted
    if s.data_notes:
        out.append(
            Section(
                id="notes", title="Data Notes", kind="bullets", items=s.data_notes, style="info"
            )
        )
    without_heap = s.total_event_count - s.heap.events_with_heap_data
    out.append(
        _kv(
            "coverage",
            "Parsing Coverage",
            build_parsing_coverage_rows(ctx.coverage, s.total_event_count, without_heap),
        )
    )
    if len(ctx.file_coverages) > 1:
        out.append(_table("files", "Input Files", build_file_coverage_table(ctx.file_coverages)))
    if len(ctx.segments) > 1:
        out.append(
            _table(
                "segments",
                f"JVM Runs Found (analyzing {ctx.segment_label})",
                build_segment_table(ctx.segments),
            )
        )
    if ctx.events:
        first, last = ctx.events[0], ctx.events[-1]
        out.append(
            _kv(
                "window",
                "Time Window",
                build_time_window_rows(
                    first.timestamp,
                    last.timestamp,
                    first.uptime_seconds,
                    last.uptime_seconds,
                    first.wall_clock,
                ),
            )
        )

    # 5. Details
    if environment := build_environment_rows(s):
        out.append(_kv("environment", "JVM & Host", environment))
    if s.jvm_heap_config:
        out.append(
            _kv(
                "config",
                "JVM Heap & GC Tuning Configuration",
                build_jvm_config_rows(s.jvm_heap_config),
            )
        )
    out.append(_kv("frequency", "GC Frequency", build_frequency_rows(s)))
    if s.full_gc_causes:
        out.append(_table("full_gc_causes", "Full GC Causes", build_full_gc_cause_table(s)))
    out.append(_table("causes", "Pause Causes by Kind", build_cause_rows(s)))
    out.append(_kv("overhead", "GC Pause Time and Share", build_overhead_rows(s)))
    out.append(_kv("heap", "Heap Utilization", build_heap_rows(s)))
    out.append(_table("pauses", "Pause Time Analysis", build_pause_distribution_table(s)))
    if violations := build_pause_violation_rows(s):
        out.append(_kv("violations", "Pause Threshold Violations", violations))
    if s.top_pauses:
        top = build_top_pauses_table(s)
        out.append(_table("top_pauses", f"Top {len(top[1])} Longest Pauses", top))

    out.append(_kv("floor", "Post-GC Occupancy Trend", build_floor_rows(s)))
    if s.floor_trend.floors:
        out.append(_table("floors", "Post-GC Occupancy Samples", build_floor_table(s)))
    if old_rows := build_old_gen_rows(s):
        out.append(_kv("old_gen", "Old Generation", old_rows))
    if s.period_stats:
        out.append(_table("periods", "Trend (Early / Middle / Late)", build_trend_table(s)))
    if alloc := build_allocation_rows(s):
        out.append(_kv("allocation", "Allocation Pressure", alloc))
    if s.g1_metrics:
        out.append(_kv("g1", "G1 GC Metrics", build_g1_rows(s)))
    if s.cms_metrics:
        out.append(_kv("cms", "CMS GC Metrics", build_cms_rows(s)))
    if concurrent := build_concurrent_rows(s):
        out.append(_kv("concurrent", "Concurrent GC Work", concurrent))
    if cpu := build_cpu_rows(s):
        out.append(_kv("cpu", "GC CPU Time", cpu))
    if safepoints := build_safepoint_rows(s):
        out.append(_kv("safepoints", "Safepoint Timing", safepoints))
    if s.metaspace_analysis:
        out.append(_kv("metaspace", "Metaspace", build_metaspace_rows(s)))

    leak = s.leak
    leak_text = f"Verdict: {LEAK_VERDICT_TEXT[leak.verdict]}"
    if leak.basis:
        leak_text += f"\nMeasured from: {leak.basis}"
    if leak.evidence:
        leak_text += "\n" + "\n".join(f"• {item}" for item in leak.evidence)
    out.append(
        Section(
            id="leak",
            title="Retention Assessment",
            kind="text",
            text=leak_text,
            style=_leak_style(s),
        )
    )
    return out


def _leak_style(summary: GCSummary) -> Style:
    verdict = summary.leak.verdict
    if verdict in ("growing", "step_change", "full"):
        return "warning"
    return "success" if verdict == "none" else "info"


# ============================================================
# RICH RENDERING
# ============================================================

_BORDER = {
    "": "white",
    "info": "cyan",
    "warning": "yellow",
    "critical": "red",
    "success": "green",
    "header": "magenta",
}


def finding_lines(finding: Finding) -> list[tuple[str, str]]:
    """The labelled lines under a finding's title (shared by terminal and Markdown)."""
    lines: list[tuple[str, str]] = []
    if finding.when:
        lines.append(("When", finding.when))
    lines += [("Evidence", item) for item in finding.evidence]
    lines.append(("Confidence", finding.confidence))
    if finding.action:
        lines.append(("Action", finding.action))
    if finding.source:
        lines.append(("Reference", finding.source))
    return lines


def _rich_section(section: Section) -> Panel | Table:
    if section.kind == "kv":
        table = Table(title=section.title, show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="label", overflow="fold")
        table.add_column("Value", style="metric", overflow="fold")
        for label, value in section.rows:
            style = "warning" if label.startswith("⚠") else None
            table.add_row(escape(label), escape(value), style=style)
        return table
    if section.kind == "table":
        table = Table(title=section.title, show_header=True, header_style="header")
        for index, header in enumerate(section.headers):
            # fold, never "…": a cut-off time or cause is worse than a tall row
            table.add_column(header, style="info" if index == 0 else "metric", overflow="fold")
        for row in section.table_rows:
            table.add_row(*(escape(cell) for cell in row))
        return table
    if section.kind == "bullets":
        text = Text()
        for index, item in enumerate(section.items):
            item_style = (
                "critical"
                if item.startswith("CRITICAL")
                else "warning"
                if item.startswith("WARNING")
                else section.style or "info"
            )
            text.append("• ", style=item_style)
            text.append(item + ("\n" if index < len(section.items) - 1 else ""), style=item_style)
        return Panel(text, title=section.title, border_style=_BORDER[section.style])
    if section.kind == "findings":
        text = Text()
        if not section.findings:
            text.append(section.text, style="success")
        for number, finding in enumerate(section.findings, 1):
            style = "info" if finding.severity == "info" else finding.severity
            text.append(f"{number}. [{finding.severity.upper()}] {finding.title}\n", style=style)
            for label, value in finding_lines(finding):
                text.append(f"   {label}: ", style="label")
                text.append(f"{value}\n", style="metric")
            if number < len(section.findings):
                text.append("\n")
        return Panel(text, title=section.title, border_style=_BORDER[section.style])
    if section.id == "header":
        return Panel(Text(f"GC Type: {section.text}"), style="header", expand=True)
    return Panel(
        Text(section.text, style=section.style or "info"),
        title=section.title,
        border_style=_BORDER[section.style],
    )


def render_rich(sections: list[Section], target: Console | None = None) -> None:
    """Print the report to the terminal."""
    out = target or console
    out.print()
    for section in sections:
        out.print(_rich_section(section))
        out.print()


def build_jvm_config_rows(config: JVMHeapConfig) -> list[tuple[str, str]]:
    """Build JVM heap and GC configuration rows."""
    rows: list[tuple[str, str]] = []

    # Heap Sizing
    if config.initial_heap_size_bytes:
        rows.append(
            ("Initial Heap Size (-Xms)", config.format_size(config.initial_heap_size_bytes))
        )
    if config.min_heap_size_bytes:
        rows.append(("Minimum Heap Size", config.format_size(config.min_heap_size_bytes)))
    if config.max_heap_size_bytes:
        rows.append(("Maximum Heap Size (-Xmx)", config.format_size(config.max_heap_size_bytes)))
    if config.heap_dump_on_out_of_memory_error is True:
        rows.append(("Heap Dump On OutOfMemoryError", "enabled"))
    if config.new_size_bytes:
        # -XX:NewSize alone is only the starting/minimum size; the young generation is fixed
        # (what -Xmn sets) only when MaxNewSize equals it.
        fixed = config.max_new_size_bytes == config.new_size_bytes
        label = (
            "New Generation Size (-Xmn)"
            if fixed
            else "New Generation Size, initial/minimum only (-XX:NewSize)"
        )
        rows.append((label, config.format_size(config.new_size_bytes)))
    if config.max_new_size_bytes:
        rows.append(("Max New Generation Size", config.format_size(config.max_new_size_bytes)))
    if config.old_size_bytes:
        rows.append(("Old Generation Size", config.format_size(config.old_size_bytes)))
    if config.max_ram_bytes:
        rows.append(("Max RAM", config.format_size(config.max_ram_bytes)))
    if config.initial_ram_percentage is not None:
        rows.append(("Initial RAM %", f"{config.initial_ram_percentage}%"))
    if config.min_ram_percentage is not None:
        rows.append(("Min RAM %", f"{config.min_ram_percentage}%"))
    if config.max_ram_percentage is not None:
        rows.append(("Max RAM %", f"{config.max_ram_percentage}%"))
    if config.max_ram_fraction is not None:
        rows.append(("Max RAM Fraction", str(config.max_ram_fraction)))
    if config.soft_max_heap_size_bytes:
        rows.append(("Soft Max Heap Size", config.format_size(config.soft_max_heap_size_bytes)))
    if config.always_pre_touch is True:
        rows.append(("Always Pre Touch", "enabled"))
    if config.thread_stack_size_kb is not None:
        rows.append(("Thread Stack Size", f"{config.thread_stack_size_kb}K"))

    # Ratios and Thresholds
    if config.new_ratio is not None:
        rows.append(("New Ratio (Old/New)", str(config.new_ratio)))
    if config.survivor_ratio is not None:
        rows.append(("Survivor Ratio (Eden/Survivor)", str(config.survivor_ratio)))
    if config.initial_survivor_ratio is not None:
        rows.append(("Initial Survivor Ratio", str(config.initial_survivor_ratio)))
    if config.target_survivor_ratio is not None:
        rows.append(("Target Survivor Ratio", f"{config.target_survivor_ratio}%"))
    if config.max_tenuring_threshold is not None:
        rows.append(("Max Tenuring Threshold", str(config.max_tenuring_threshold)))
    if config.min_heap_free_ratio is not None:
        rows.append(("Min Heap Free Ratio", f"{config.min_heap_free_ratio}%"))
    if config.max_heap_free_ratio is not None:
        rows.append(("Max Heap Free Ratio", f"{config.max_heap_free_ratio}%"))

    # Metaspace
    if config.metaspace_size_bytes:
        rows.append(("Metaspace Size", config.format_size(config.metaspace_size_bytes)))
    if config.max_metaspace_size_bytes:
        rows.append(("Max Metaspace Size", config.format_size(config.max_metaspace_size_bytes)))
    if config.max_direct_memory_size_bytes:
        rows.append(
            ("Max Direct Memory Size", config.format_size(config.max_direct_memory_size_bytes))
        )

    # GC Threading
    if config.parallel_gc_threads is not None:
        rows.append(("Parallel GC Threads", str(config.parallel_gc_threads)))
    if config.conc_gc_threads is not None:
        rows.append(("Concurrent GC Threads", str(config.conc_gc_threads)))

    # GC Behavior Tuning
    if config.max_gc_pause_millis is not None:
        rows.append(("Max GC Pause Target", f"{config.max_gc_pause_millis}ms"))
    if config.gc_time_ratio is not None:
        rows.append(("GC Time Ratio", str(config.gc_time_ratio)))
    if config.adaptive_size_policy_weight is not None:
        rows.append(("Adaptive Size Policy Weight", str(config.adaptive_size_policy_weight)))
    if config.use_adaptive_size_policy is True:
        rows.append(("Adaptive Size Policy", "enabled"))
    if config.use_adaptive_size_policy_footprint_goal is True:
        rows.append(("Adaptive Size Policy Footprint Goal", "enabled"))

    # G1-Specific
    if config.g1_heap_region_size_bytes:
        rows.append(("G1 Heap Region Size", config.format_size(config.g1_heap_region_size_bytes)))
    if config.initiating_heap_occupancy_percent is not None:
        rows.append(("Initiating Heap Occupancy %", f"{config.initiating_heap_occupancy_percent}%"))
    if config.g1_reserve_percent is not None:
        rows.append(("G1 Reserve Percent", f"{config.g1_reserve_percent}%"))
    if config.g1_new_size_percent is not None:
        rows.append(("G1 New Size Percent", f"{config.g1_new_size_percent}%"))
    if config.g1_max_new_size_percent is not None:
        rows.append(("G1 Max New Size Percent", f"{config.g1_max_new_size_percent}%"))
    if config.g1_mixed_gc_count_target is not None:
        rows.append(("G1 Mixed GC Count Target", str(config.g1_mixed_gc_count_target)))
    if config.g1_heap_waste_percent is not None:
        rows.append(("G1 Heap Waste Percent", f"{config.g1_heap_waste_percent}%"))
    if config.g1_mixed_gc_live_threshold_percent is not None:
        rows.append(
            (
                "G1 Mixed GC Live Threshold Percent",
                f"{config.g1_mixed_gc_live_threshold_percent}%",
            )
        )
    if config.g1_rset_updating_pause_time_percent is not None:
        rows.append(
            (
                "G1 RSet Updating Pause Time Percent",
                f"{config.g1_rset_updating_pause_time_percent}%",
            )
        )
    if config.g1_old_cset_region_threshold_percent is not None:
        rows.append(
            (
                "G1 Old CSet Region Threshold Percent",
                f"{config.g1_old_cset_region_threshold_percent}%",
            )
        )

    # CMS-Specific
    if config.cms_initiating_occupancy_fraction is not None:
        rows.append(
            (
                "CMS Initiating Occupancy Fraction",
                f"{config.cms_initiating_occupancy_fraction}%",
            )
        )
    if config.use_cms_initiating_occupancy_only is True:
        rows.append(("Use CMS Initiating Occupancy Only", "enabled"))
    if config.cms_full_gcs_before_compaction is not None:
        rows.append(("CMS Full GCs Before Compaction", str(config.cms_full_gcs_before_compaction)))
    if config.cms_wait_duration is not None:
        rows.append(("CMS Wait Duration", f"{config.cms_wait_duration}ms"))

    return rows
