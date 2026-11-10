"""Report content: one list of sections rendered both to the terminal (Rich) and Markdown.

``build_sections`` decides *what* the report says; ``render_rich`` and
``markdown.render_markdown`` only decide how it looks, so both outputs always agree.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from .analysis import format_duration, max_events_in_window
from .coverage import build_unparsed_warning
from .models import (
    GC_KINDS,
    CandidateCoverage,
    FileCoverage,
    GCEvent,
    GCSummary,
    JVMHeapConfig,
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

SectionKind = Literal["kv", "table", "text", "bullets"]
Style = Literal["", "info", "warning", "critical", "success", "header"]


@dataclass
class Section:
    """One block of the report."""

    id: str
    title: str
    kind: SectionKind
    rows: list[tuple[str, str]] = field(default_factory=list[tuple[str, str]])
    headers: list[str] = field(default_factory=list[str])
    table_rows: list[list[str]] = field(default_factory=list[list[str]])
    text: str = ""
    items: list[str] = field(default_factory=list[str])
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
    comparison: GCSummary | None = None  # same window 24 h earlier (P2.2)
    comparison_label: str = ""
    inputs: list[str] = field(default_factory=list[str])


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


def _format_bytes_human(size_bytes: int) -> str:
    """Bytes as '3.0G' (JVM flag style)."""
    if size_bytes >= 1024**3:
        return f"{size_bytes / (1024**3):.1f}G"
    if size_bytes >= 1024**2:
        return f"{size_bytes / (1024**2):.1f}M"
    if size_bytes >= 1024:
        return f"{size_bytes / 1024:.1f}K"
    return f"{size_bytes}B"


def format_time(timestamp: datetime, wall_clock: bool, uptime: float | None) -> str:
    """Wall-clock ISO time, or JVM uptime when the log has no wall clock."""
    if wall_clock:
        return timestamp.isoformat(timespec="milliseconds")
    return f"uptime {uptime:.3f}s" if uptime is not None else "n/a"


def event_time(event: GCEvent) -> str:
    """Display time of an event."""
    return format_time(event.timestamp, event.wall_clock, event.uptime_seconds)


def describe_pause(event: GCEvent) -> str:
    """'Full (Allocation Failure)' / 'Young (G1 Evacuation Pause)'."""
    flags: list[str] = []
    if event.concurrent_mode_failure:
        flags.append("concurrent mode failure")
    if event.promotion_failed:
        flags.append("promotion failed")
    if event.to_space_exhausted or event.evacuation_failed:
        flags.append("evacuation failure")
    cause = event.cause or "cause not logged"
    suffix = f"; {', '.join(flags)}" if flags else ""
    return f"{event.gc_kind} ({cause}{suffix})"


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


def _interpret_gc_overhead(overhead_pct: float) -> str:
    if overhead_pct > 20:
        return "critical, application severely impacted; target <5%"
    if overhead_pct > 10:
        return "elevated, investigate allocation hotspots; target <5%"
    if overhead_pct > 5:
        return "moderate; target <5%"
    return "healthy"


def _interpret_p99_pause(p99_seconds: float) -> str:
    if p99_seconds > 10:
        return "1-in-100 pauses this long; severe impact on latency"
    if p99_seconds > 5:
        return "1-in-100 pauses this long; may impact latency-sensitive workloads"
    if p99_seconds > 1:
        return "1-in-100 pauses this long; monitor for latency impact"
    return "1-in-100 pauses this long; within normal range"


def build_at_a_glance_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Compact headline metrics."""
    heap = summary.heap
    basis = "max heap" if heap.max_heap_known else "committed heap"
    trend = summary.floor_trend
    if trend.assessed and trend.slope_mb_per_hour is not None:
        floor_text = f"{trend.slope_mb_per_hour:+.1f} MB/h over {trend.span_hours:.1f} h"
    else:
        floor_text = f"not assessed: {trend.reason}"
    return [
        ("Window", format_duration(summary.runtime_seconds)),
        ("GC pauses", str(summary.total_event_count)),
        (
            "GC overhead (pause time)",
            f"{summary.gc_overhead_pct:.2f}% ({_interpret_gc_overhead(summary.gc_overhead_pct)})",
        ),
        (
            "P99 STW pause",
            (
                f"{summary.overall_pauses.p99:.3f}s "
                f"({_interpret_p99_pause(summary.overall_pauses.p99)})"
            ),
        ),
        ("Longest pause", format_seconds(summary.overall_pauses.maximum)),
        (
            "Heap after GC (peak)",
            f"{heap.peak_after_gc_pct:.1f}% of {basis}" if heap.events_with_heap_data else "n/a",
        ),
        (
            "Heap-pressure Full GCs",
            _rate_or_count(summary.heap_full_gc_count, summary.full_gc_per_hour, summary),
        ),
        ("Old-gen floor trend", floor_text),
        (
            "Leak level",
            summary.leak_severity.severity_level
            if summary.leak_severity.assessed
            else "not assessed",
        ),
    ]


def build_runtime_overview_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Window and pause counts by kind."""
    rows = [
        (
            "Observed window",
            f"{format_duration(summary.runtime_seconds)} ({summary.runtime_seconds:.0f} seconds)",
        ),
        ("Total pauses", str(summary.total_event_count)),
    ]
    rows += [
        (f"{kind} pauses", str(summary.counts_by_kind[kind]))
        for kind in GC_KINDS
        if kind in summary.counts_by_kind
    ]
    return rows


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
            ("Avg time between heap Full GCs", f"{summary.avg_full_gc_interval_min:.1f} minutes")
        )
    if summary.min_full_gc_interval_min is not None:
        rows.append(
            (
                "Shortest gap between heap Full GCs",
                f"{summary.min_full_gc_interval_min:.1f} minutes",
            )
        )
    if summary.time_to_first_full_gc_hours is not None:
        rows.append(
            ("Time to first heap Full GC", f"{summary.time_to_first_full_gc_hours:.2f} hours")
        )
    if summary.max_full_gc_streak > 1:
        rows.append(("Most heap Full GCs within 5 min", str(summary.max_full_gc_streak)))
    return rows


def build_full_gc_cause_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Full GC counts by cause (P1.2)."""
    labels = {
        "heap": "heap pressure",
        "explicit": "explicit (excluded from rates)",
        "metadata": "metaspace",
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
    return [
        ("Total time in GC pauses", f"{summary.total_gc_time_sec:.1f} seconds"),
        ("GC overhead", f"{summary.gc_overhead_pct:.2f}%"),
        ("Application throughput", f"{summary.throughput_pct:.2f}%"),
    ]


def build_heap_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Heap before/after GC against max heap (P1.3)."""
    heap = summary.heap
    if not heap.events_with_heap_data:
        return [("Heap data", "not in log")]
    basis = "max heap" if heap.max_heap_known else "committed heap"
    max_text = format_kb(heap.max_heap_kb) if heap.max_heap_kb else "unknown"
    return [
        (
            "Max heap",
            f"{max_text} (from {heap.max_heap_source})"
            if heap.max_heap_known
            else f"unknown; percentages use the committed heap, {max_text}",
        ),
        (
            "Peak before GC",
            f"{format_kb(heap.peak_before_gc_kb)} ({heap.peak_before_gc_pct:.1f}% of {basis})",
        ),
        (
            "Peak after GC (live set upper bound)",
            f"{format_kb(heap.peak_after_gc_kb)} ({heap.peak_after_gc_pct:.1f}% of {basis})",
        ),
        (
            "Average after GC",
            f"{format_kb(heap.avg_after_gc_kb)} ({heap.avg_after_gc_pct:.1f}% of {basis})",
        ),
        ("Headroom after GC", f"{heap.headroom_pct:.1f}%"),
        ("Pauses with heap sizes", str(heap.events_with_heap_data)),
    ]


def build_pause_distribution_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Pause distribution by kind."""
    headers = ["GC Type", "Count", "Total", "Average", "Median", "P95", "P99", "Maximum"]

    def row(label: str, stats_key: str | None) -> list[str]:
        stats = summary.overall_pauses if stats_key is None else summary.pauses_by_kind[stats_key]
        return [
            label,
            str(stats.count),
            format_seconds(stats.total),
            format_seconds(stats.average),
            format_seconds(stats.median),
            format_seconds(stats.p95),
            format_seconds(stats.p99),
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


def build_top_pauses_table(events: list[GCEvent], top_n: int) -> tuple[list[str], list[list[str]]]:
    """Longest pauses with time, kind, cause and heap."""
    headers = ["Time", "Pause", "Kind (cause)", "Heap before → after", "Old gen after"]
    rows: list[list[str]] = []
    for event in heapq.nlargest(top_n, events, key=lambda e: e.pause_time_seconds):
        heap_text = (
            f"{format_kb(event.heap_before_kb)} → {format_kb(event.heap_after_kb)} "
            f"of {format_kb(event.heap_total_kb)}"
            if event.has_heap_data
            else "—"
        )
        old_text = (
            f"{event.old_used_percentage:.1f}%" if event.old_used_percentage is not None else "—"
        )
        rows.append(
            [
                event_time(event),
                format_seconds(event.pause_time_seconds),
                describe_pause(event),
                heap_text,
                old_text,
            ]
        )
    return headers, rows


def build_floor_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Old-gen floor trend headline (P1.1)."""
    trend = summary.floor_trend
    what = "old generation" if trend.metric == "old" else "whole heap"
    rows = [("Measured", f"{what} right after collections that clean it")]
    if trend.capacity_kb:
        rows.append(
            ("Capacity used for %", f"{format_kb(trend.capacity_kb)} ({trend.capacity_source})")
        )
    rows.append(("Floors", str(len(trend.floors))))
    if trend.first_mb is not None and trend.last_mb is not None:
        rows.append(
            (
                "First → last floor",
                f"{format_kb(trend.floors[0].value_kb)} → {format_kb(trend.floors[-1].value_kb)}",
            )
        )
    if trend.assessed and trend.slope_mb_per_hour is not None:
        pct = (
            f" ({trend.slope_pct_per_hour:+.2f}% of capacity/h)"
            if trend.slope_pct_per_hour is not None
            else ""
        )
        rows.append(("Slope", f"{trend.slope_mb_per_hour:+.1f} MB/h{pct}"))
        rows.append(("Fit (r²)", f"{trend.r_squared:.2f}"))
        rows.append(("Span", f"{trend.span_hours:.1f} h"))
    else:
        rows.append(("Trend", f"not assessed: {trend.reason}"))
    return rows


def build_floor_table(summary: GCSummary, limit: int = 30) -> tuple[list[str], list[list[str]]]:
    """Individual floors so the reader can see the trend themselves."""
    headers = ["Time", "After", "Occupancy", "% of capacity"]
    floors = summary.floor_trend.floors
    if len(floors) > limit:  # keep first, last and an even spread
        step = (len(floors) - 1) / (limit - 1)
        floors = [floors[round(i * step)] for i in range(limit)]
    rows = [
        [
            format_time(f.timestamp, f.wall_clock, f.uptime_seconds),
            f.source,
            format_kb(f.value_kb),
            f"{f.pct_of_capacity:.1f}%" if f.pct_of_capacity is not None else "—",
        ]
        for f in floors
    ]
    return headers, rows


def build_old_gen_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Old-gen occupancy (sawtooth) and Full GC effectiveness."""
    rows: list[tuple[str, str]] = []
    if summary.peak_old_pct is not None and summary.avg_old_pct is not None:
        rows.append(("Peak old gen after GC", f"{summary.peak_old_pct:.1f}%"))
        rows.append(("Average old gen after GC", f"{summary.avg_old_pct:.1f}%"))
    if summary.full_gc_count:
        rows.append(("Avg reclaimed per Full GC", format_kb(summary.avg_reclaimed_kb)))
        rows.append(
            ("Full GCs reducing old gen", f"{summary.full_gc_reducing}/{summary.full_gc_count}")
        )
        if summary.avg_post_full_gc_pct is not None:
            rows.append(("Avg old gen after Full GC", f"{summary.avg_post_full_gc_pct:.1f}%"))
        if summary.reclamation_declining:
            rows.append(("⚠ Reclamation declining over time", "yes"))
    return rows


def build_trend_table(summary: GCSummary) -> tuple[list[str], list[list[str]]]:
    """Early / middle / late thirds of the window."""
    headers = ["Period", "Avg old gen after GC", "Full GCs"]
    rows: list[list[str]] = []
    for name in ("early", "middle", "late"):
        if period := summary.period_stats.get(name):
            avg = period.average_old_gen_percentage
            rows.append(
                [name, f"{avg:.1f}%" if avg is not None else "—", str(period.full_gc_count)]
            )
    return headers, rows


def build_allocation_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Allocation between GCs (P1.8) and promotion."""
    rows: list[tuple[str, str]] = []
    if summary.allocation_rate_mb_sec is not None:
        rows.append(
            (
                "Allocation rate (between GCs)",
                f"{summary.allocation_rate_mb_sec:.2f} MB/s ({summary.allocation_basis})",
            )
        )
    if summary.avg_promotion_kb:
        rows.append(("Average promotion per young GC", format_kb(summary.avg_promotion_kb)))
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
    return [
        ("Mixed GC count", str(g1.mixed_gc_count)),
        ("Mixed GCs per hour", per_hour),
        ("Concurrent marking cycles", str(g1.concurrent_marking_cycles)),
        ("Pauses triggered by humongous allocation", str(g1.humongous_allocation_count)),
        ("Evacuation failures", str(g1.evacuation_failure_count)),
        ("To-space exhausted", str(g1.to_space_exhausted_count)),
    ]


def build_cms_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """CMS metrics (P1.6)."""
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
        ("Promotion failures", str(cms.promotion_failures)),
    ]
    if cms.concurrent_mode_failures:
        rows.append(("⚠ Old gen filled before the concurrent cycle finished", ""))
    return rows


def build_metaspace_rows(summary: GCSummary) -> list[tuple[str, str]]:
    """Metaspace usage and metaspace-triggered Full GCs."""
    meta = summary.metaspace_analysis
    if not meta:
        return []
    rows = [
        ("Peak metaspace usage", f"{meta.peak_metaspace_used_percentage:.1f}%"),
        ("Metaspace growth", f"{meta.metaspace_growth_kb // 1024} MB"),
    ]
    if meta.metadata_full_gc_count:
        rows.append(("Full GCs triggered by metaspace", str(meta.metadata_full_gc_count)))
    return rows


def build_segment_table(segments: list[SegmentInfo]) -> tuple[list[str], list[list[str]]]:
    """JVM runs found in the input (P1.9)."""
    headers = ["Segment", "First event", "Last event", "Pauses", "Files"]
    rows = [
        [
            str(s.index),
            format_time(s.first_timestamp, s.wall_clock, s.first_uptime_seconds),
            format_time(s.last_timestamp, s.wall_clock, s.last_uptime_seconds),
            str(s.events),
            ", ".join(s.files),
        ]
        for s in segments
    ]
    return headers, rows


def build_comparison_table(
    current: GCSummary, previous: GCSummary
) -> tuple[list[str], list[list[str]]]:
    """Incident window vs. the same window a day earlier (P2.2)."""
    headers = ["Metric", "This window", "Same window, previous day"]

    def heap_after(s: GCSummary) -> str:
        return f"{s.heap.peak_after_gc_pct:.1f}%" if s.heap.events_with_heap_data else "—"

    rows = [
        ["Pauses", str(current.total_event_count), str(previous.total_event_count)],
        [
            "Time in GC",
            format_seconds(current.total_gc_time_sec),
            format_seconds(previous.total_gc_time_sec),
        ],
        ["GC overhead", f"{current.gc_overhead_pct:.2f}%", f"{previous.gc_overhead_pct:.2f}%"],
        [
            "P99 pause",
            format_seconds(current.overall_pauses.p99),
            format_seconds(previous.overall_pauses.p99),
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
    """One sentence on the live-set trend."""
    trend = summary.floor_trend
    if not trend.floors:
        return f"Live set: not assessed: {trend.reason}."
    what = "Old-gen" if trend.metric == "old" else "Heap"
    first_last = f"{format_kb(trend.floors[0].value_kb)} → {format_kb(trend.floors[-1].value_kb)}"
    if not trend.assessed or trend.slope_mb_per_hour is None:
        return (
            f"Live set: {what} floor {first_last} over {len(trend.floors)} floor(s); trend not "
            f"assessed: {trend.reason}."
        )
    r2 = trend.r_squared or 0.0
    if r2 < 0.5:
        direction = "no consistent trend"
    elif trend.slope_mb_per_hour > 0:
        direction = "rising"
    else:
        direction = "falling or flat"
    return (
        f"Live set: {what} floor {first_last}; {direction}, slope "
        f"{trend.slope_mb_per_hour:+.1f} MB/h (r²={r2:.2f}) over {len(trend.floors)} floors "
        f"in {trend.span_hours:.1f} h."
    )


def describe_pause_clustering(events: list[GCEvent], top_n: int = 5, window_s: float = 900) -> str:
    """Whether the longest pauses happen together (only said when the log is much longer)."""
    if len(events) < 2:
        return ""
    total_span = (events[-1].timestamp - events[0].timestamp).total_seconds()
    if total_span < window_s * 2:
        return ""
    top = sorted(
        heapq.nlargest(top_n, events, key=lambda e: e.pause_time_seconds), key=lambda e: e.timestamp
    )
    if len(top) < 3:
        return ""
    base = top[0].timestamp
    seconds = [(e.timestamp - base).total_seconds() for e in top]
    best = max_events_in_window(seconds, window_s)
    if best < 3:
        return (
            f"The {len(top)} longest pauses are spread across the window (no 3 within "
            f"{window_s / 60:.0f} min)."
        )
    for start in range(len(top)):
        inside = [
            e
            for e in top[start:]
            if (e.timestamp - top[start].timestamp).total_seconds() <= window_s
        ]
        if len(inside) == best:
            span = (inside[-1].timestamp - inside[0].timestamp).total_seconds()
            return (
                f"{best} of the {len(top)} longest pauses fall within {format_duration(span)} "
                f"({event_time(inside[0])} to {event_time(inside[-1])})."
            )
    return ""  # pragma: no cover


def build_incident_summary(ctx: ReportContext) -> list[str]:
    """Top-of-report summary for a troubleshooting session (P2.3)."""
    summary = ctx.summary
    lines: list[str] = []
    if summary.first_timestamp and summary.last_timestamp and ctx.events:
        first, last = ctx.events[0], ctx.events[-1]
        lines.append(
            f"Window: {event_time(first)} to {event_time(last)} "
            f"({format_duration(summary.runtime_seconds)}), {summary.total_event_count} pauses, "
            f"{summary.total_gc_time_sec:.1f} s in GC ({summary.gc_overhead_pct:.2f}% overhead)."
        )
    top = heapq.nlargest(5, ctx.events, key=lambda e: e.pause_time_seconds)
    if top:
        lines.append("Worst pauses:")
        lines += [
            f"  {format_seconds(e.pause_time_seconds):>14}  {event_time(e)}  {describe_pause(e)}"
            for e in top
        ]
    if clustering := describe_pause_clustering(ctx.events):
        lines.append(clustering)
    lines.append(describe_floor_trend(summary))
    if summary.full_gc_causes:
        parts = [f"{c.count} {c.cause}" for c in summary.full_gc_causes]
        lines.append(f"Full GCs: {summary.full_gc_count} ({', '.join(parts)}).")
    else:
        lines.append("Full GCs: none.")
    cov = ctx.coverage
    if cov.unparsed_candidate_lines:
        lines.append(
            f"Data quality: {cov.unparsed_candidate_lines} of {cov.candidate_lines} GC lines "
            f"({cov.unparsed_percentage:.1f}%) NOT parsed - see Parsing Coverage."
        )
    else:
        lines.append(f"Data quality: all {cov.candidate_lines} GC lines parsed.")
    return lines


def determine_quick_diagnosis(summary: GCSummary) -> str:
    """Two lines: GC health and leak risk."""
    critical = sum(1 for w in summary.warnings if w.startswith("CRITICAL"))
    warning = sum(1 for w in summary.warnings if w.startswith("WARNING"))
    if critical:
        health = "🔴 GC HEALTH: Critical issues detected"
    elif warning:
        health = "🟡 GC HEALTH: Degraded; review warnings"
    else:
        health = "✅ GC HEALTH: Stable"
    leak = summary.leak_severity
    if not leak.assessed:
        leak_line = "⚪ LEAK RISK: Not assessed (no post-collection floors)"
    elif leak.severity_level in ("Critical", "High"):
        leak_line = f"🔴 LEAK RISK: {leak.severity_level} (score {leak.score:.0f}/100)"
    elif leak.severity_level in ("Medium", "Low"):
        leak_line = f"🟡 LEAK RISK: {leak.severity_level} (score {leak.score:.0f}/100)"
    elif not summary.floor_trend.assessed:
        leak_line = "⚪ LEAK RISK: No signal, but floor trend not assessed (see Data Notes)"
    else:
        leak_line = "🟢 LEAK RISK: None detected"
    return f"{health}\n{leak_line}"


def determine_overall_status(summary: GCSummary) -> tuple[str, Style]:
    """Overall status text and style."""
    critical = sum(1 for w in summary.warnings if w.startswith("CRITICAL"))
    warning = sum(1 for w in summary.warnings if w.startswith("WARNING"))
    if critical >= 3:
        return "✖ CRITICAL - IMMEDIATE ACTION REQUIRED", "critical"
    if critical:
        return "✖ UNSTABLE - INTERVENTION REQUIRED", "critical"
    if warning:
        return "⚠ DEGRADED - MONITORING REQUIRED", "warning"
    return "✓ STABLE", "success"


def build_evidence_based_recommendations(summary: GCSummary, gc_type: str = "") -> list[str]:
    """Recommendations tied to observed metrics and the JVM's own flags."""
    recs: list[str] = []
    config = summary.jvm_heap_config
    xmx = (
        _format_bytes_human(config.max_heap_size_bytes)
        if config and config.max_heap_size_bytes
        else None
    )
    trend = summary.floor_trend

    if trend.assessed and (trend.slope_mb_per_hour or 0) > 0 and (trend.r_squared or 0) >= 0.5:
        recs.append(
            "Old-gen floor is rising; take two heap dumps hours apart (jcmd <pid> GC.heap_dump) "
            "and compare retained sizes to find what is growing"
        )
    if summary.avg_post_full_gc_pct is not None and summary.avg_post_full_gc_pct > 80:
        rec = (
            f"Old gen stays {summary.avg_post_full_gc_pct:.0f}% full after Full GC; the live set "
            "nearly fills it"
        )
        if xmx:
            rec += f". Current -Xmx is {xmx}; raise it only after ruling out a leak"
        recs.append(rec)
    if summary.explicit_full_gc_count:
        rec = (
            f"{summary.explicit_full_gc_count} explicit Full GC(s): if they come from RMI "
            "distributed GC (hourly in Tomcat), raise -Dsun.rmi.dgc.server.gcInterval and "
            "-Dsun.rmi.dgc.client.gcInterval"
        )
        if "G1" in gc_type or "CMS" in gc_type:
            rec += " or add -XX:+ExplicitGCInvokesConcurrent so System.gc() runs concurrently"
        recs.append(rec)
    if summary.metadata_full_gc_count:
        rec = "Metaspace is triggering Full GCs; raise -XX:MetaspaceSize (the first GC threshold)"
        if config and config.metaspace_size_bytes:
            rec += f" (currently {_format_bytes_human(config.metaspace_size_bytes)})"
        recs.append(rec)
    if summary.cms_metrics and (
        summary.cms_metrics.concurrent_mode_failures or summary.cms_metrics.promotion_failures
    ):
        rec = (
            "CMS failures: start cycles earlier with a lower -XX:CMSInitiatingOccupancyFraction "
            "and -XX:+UseCMSInitiatingOccupancyOnly, or give the old gen more room"
        )
        if config and config.cms_initiating_occupancy_fraction is not None:
            rec += f" (current fraction {config.cms_initiating_occupancy_fraction}%)"
        recs.append(rec)
    if summary.g1_metrics and summary.g1_metrics.evacuation_failure_count:
        rec = (
            "G1 evacuation failures: increase -XX:G1ReservePercent or the heap, or lower "
            "-XX:InitiatingHeapOccupancyPercent to start marking earlier"
        )
        if config and config.initiating_heap_occupancy_percent is not None:
            rec += f" (IHOP currently {config.initiating_heap_occupancy_percent}%)"
        recs.append(rec)
    if (
        summary.g1_metrics
        and summary.g1_metrics.humongous_allocation_count > summary.total_event_count * 0.05
    ):
        rec = (
            f"{summary.g1_metrics.humongous_allocation_count} pauses were triggered by "
            "humongous allocations (objects ≥ half a G1 region)"
        )
        if config and config.g1_heap_region_size_bytes:
            rec += (
                "; current "
                f"-XX:G1HeapRegionSize={_format_bytes_human(config.g1_heap_region_size_bytes)}, "
                "consider a larger region"
            )
        else:
            rec += "; consider a larger -XX:G1HeapRegionSize"
        recs.append(rec)
    if summary.gc_overhead_pct > 10:
        recs.append(
            f"GC overhead {summary.gc_overhead_pct:.1f}%: reduce allocation rate or resize the "
            "heap/young gen"
        )
    if summary.overall_pauses.p99 > 5:
        recs.append(
            "P99 pause above 5s: look at the Worst pauses list for the kind and cause to tune"
        )
    if summary.max_full_gc_streak >= 3:
        recs.append(
            "Back-to-back heap Full GCs: the heap is nearly full of live data; "
            "capture a heap dump now"
        )
    heap = summary.heap
    if heap.events_with_heap_data and heap.max_heap_known and heap.headroom_pct < 10:
        rec = f"Only {heap.headroom_pct:.1f}% headroom after GC against max heap"
        if xmx and config and config.max_heap_size_bytes:
            rec += (
                f"; current -Xmx {xmx}, consider "
                f"{_format_bytes_human(int(config.max_heap_size_bytes * 1.25))} after leak triage"
            )
        recs.append(rec)
    if (
        summary.metaspace_analysis
        and summary.metaspace_analysis.peak_metaspace_used_percentage > 90
    ):
        recs.append("Metaspace above 90%: check for classloader leaks or raise MaxMetaspaceSize")
    if summary.allocation_rate_mb_sec and summary.allocation_rate_mb_sec > 500:
        recs.append(
            f"High allocation rate ({summary.allocation_rate_mb_sec:.0f} MB/s): profile "
            "allocation hotspots"
        )
    return recs


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
    out.append(
        Section(
            id="incident",
            title="Incident Summary",
            kind="text",
            text="\n".join(build_incident_summary(ctx)),
            style="info",
        )
    )
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
    if ctx.comparison is not None:
        out.append(
            _table(
                "comparison",
                f"Compared with {ctx.comparison_label}",
                build_comparison_table(s, ctx.comparison),
            )
        )
    if s.jvm_heap_config:
        out.append(
            _kv(
                "config",
                "JVM Heap & GC Tuning Configuration",
                build_jvm_config_rows(s.jvm_heap_config),
            )
        )

    out.append(
        Section(
            id="diagnosis",
            title="Quick Diagnosis",
            kind="text",
            text=determine_quick_diagnosis(s),
            style=_diagnosis_style(s),
        )
    )
    out.append(_kv("glance", "At-a-Glance", build_at_a_glance_rows(s)))
    out.append(_kv("overview", "JVM Runtime Overview", build_runtime_overview_rows(s)))
    out.append(_kv("frequency", "GC Frequency", build_frequency_rows(s)))
    if s.full_gc_causes:
        out.append(_table("full_gc_causes", "Full GC Causes", build_full_gc_cause_table(s)))
    out.append(_table("causes", "Pause Causes by Kind", build_cause_rows(s)))
    out.append(_kv("overhead", "GC Overhead & Throughput", build_overhead_rows(s)))
    out.append(_kv("heap", "Heap Utilization", build_heap_rows(s)))
    out.append(_table("pauses", "Pause Time Analysis", build_pause_distribution_table(s)))
    if violations := build_pause_violation_rows(s):
        out.append(_kv("violations", "Pause Threshold Violations", violations))
    if ctx.events:
        top = build_top_pauses_table(ctx.events, 10)
        out.append(_table("top_pauses", f"Top {len(top[1])} Longest Pauses", top))

    out.append(_kv("floor", "Old-Gen Floor Trend (leak signal)", build_floor_rows(s)))
    if s.floor_trend.floors:
        out.append(
            _table("floors", "Floors (occupancy after cleaning collections)", build_floor_table(s))
        )
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
    if s.metaspace_analysis:
        out.append(_kv("metaspace", "Metaspace", build_metaspace_rows(s)))

    leak = s.leak_severity
    leak_text = (
        f"Leak severity score: {leak.score:.1f}/100\nLevel: "
        f"{leak.severity_level if leak.assessed else 'not assessed'}"
    )
    if leak.indicators:
        leak_text += "\n" + "\n".join(f"• {i}" for i in leak.indicators)
    out.append(
        Section(
            id="leak",
            title="Memory Leak Assessment",
            kind="text",
            text=leak_text,
            style=_leak_style(s),
        )
    )
    if recs := build_evidence_based_recommendations(s, ctx.gc_type):
        out.append(
            Section(
                id="recommendations",
                title="Evidence-Based Recommendations",
                kind="bullets",
                items=recs,
                style="info",
            )
        )
    if s.warnings:
        style: Style = (
            "critical" if any(w.startswith("CRITICAL") for w in s.warnings) else "warning"
        )
        out.append(
            Section(id="warnings", title="Warnings", kind="bullets", items=s.warnings, style=style)
        )
    status, status_style = determine_overall_status(s)
    out.append(
        Section(id="status", title="Overall Status", kind="text", text=status, style=status_style)
    )
    return out


def _diagnosis_style(summary: GCSummary) -> Style:
    text = determine_quick_diagnosis(summary)
    if "🔴" in text:
        return "critical"
    if "🟡" in text:
        return "warning"
    return "success"


def _leak_style(summary: GCSummary) -> Style:
    level = summary.leak_severity.severity_level
    if level in ("High", "Critical"):
        return "critical"
    if level in ("Low", "Medium"):
        return "warning"
    return "success"


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


def _rich_section(section: Section) -> Panel | Table:
    if section.kind == "kv":
        table = Table(title=section.title, show_header=False, box=None, padding=(0, 2))
        table.add_column("Metric", style="label")
        table.add_column("Value", style="metric")
        for label, value in section.rows:
            style = "warning" if label.startswith("⚠") else None
            table.add_row(escape(label), escape(value), style=style)
        return table
    if section.kind == "table":
        table = Table(title=section.title, show_header=True, header_style="header")
        for index, header in enumerate(section.headers):
            table.add_column(header, style="info" if index == 0 else "metric")
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
    if config.max_heap_size_bytes:
        rows.append(("Maximum Heap Size (-Xmx)", config.format_size(config.max_heap_size_bytes)))
    if config.new_size_bytes:
        rows.append(("New Generation Size (-Xmn)", config.format_size(config.new_size_bytes)))
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
