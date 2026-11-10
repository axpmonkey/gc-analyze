"""Diagnostics: summary statistics, leak scoring and collector metrics."""

from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Literal

from .models import (
    GC_KINDS,
    CMSMetrics,
    DiagnosticThresholds,
    FloorPoint,
    FloorTrend,
    FullGCCategory,
    FullGCCause,
    G1Metrics,
    GCEvent,
    GCSummary,
    HeapStats,
    JVMHeapConfig,
    LeakSeverity,
    MetaspaceAnalysis,
    PauseStats,
    PeriodStatistics,
)

# ============================================================
# FULL GC CAUSES (P1.2)
# ============================================================

# Full GCs requested by code or tooling, not by heap pressure (e.g. Tomcat's RMI DGC calls
# System.gc() hourly). Still reported, but excluded from Full GC rates, streaks,
# acceleration and leak scoring.
EXPLICIT_FULL_GC_CAUSES: frozenset[str] = frozenset(
    {
        "System.gc()",
        "Heap Inspection Initiated GC",
        "Heap Dump Initiated GC",
        "Diagnostic Command",
        "JvmtiEnv ForceGarbageCollector",
        "WhiteBox Initiated Full GC",
        "Full GC Alot",
    }
)
# Full GCs triggered by metaspace, not the Java heap: routed to the metaspace section.
METADATA_FULL_GC_CAUSES: frozenset[str] = frozenset(
    {"Metadata GC Threshold", "Metadata GC Clear Soft References", "Last ditch collection"}
)


def classify_full_gc_cause(cause: str | None) -> FullGCCategory:
    """Category of a Full GC cause: explicit request, metaspace, or heap pressure."""
    if cause in EXPLICIT_FULL_GC_CAUSES:
        return "explicit"
    if cause in METADATA_FULL_GC_CAUSES:
        return "metadata"
    return "heap"


def is_heap_pressure_full_gc(event: GCEvent) -> bool:
    """Full GC caused by the Java heap (not System.gc() and not metaspace)."""
    return event.gc_kind == "Full" and classify_full_gc_cause(event.cause) == "heap"


# ============================================================
# SMALL HELPERS
# ============================================================


def percentile_sorted(sorted_data: list[float], pct: float) -> float:
    """Linear-interpolated percentile of a pre-sorted list."""
    if not sorted_data:
        return 0.0
    k = (len(sorted_data) - 1) * (pct / 100)
    f = int(k)
    c = k - f
    if f + 1 < len(sorted_data):
        return sorted_data[f] + c * (sorted_data[f + 1] - sorted_data[f])
    return sorted_data[f]


def pause_stats(values: list[float]) -> PauseStats:
    """Distribution of pause times."""
    if not values:
        return PauseStats()
    ordered = sorted(values)
    return PauseStats(
        count=len(ordered),
        total=sum(ordered),
        average=mean(ordered),
        median=percentile_sorted(ordered, 50),
        p95=percentile_sorted(ordered, 95),
        p99=percentile_sorted(ordered, 99),
        maximum=ordered[-1],
    )


def linear_fit(xs: list[float], ys: list[float]) -> tuple[float, float] | None:
    """Least-squares slope and r^2; None when x has no spread."""
    n = len(xs)
    mean_x, mean_y = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mean_x) ** 2 for x in xs)
    if sxx == 0:
        return None
    sxy = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    syy = sum((y - mean_y) ** 2 for y in ys)
    slope = sxy / sxx
    r_squared = (sxy * sxy) / (sxx * syy) if syy > 0 else 1.0
    return slope, r_squared


def format_duration(seconds: float) -> str:
    """'45 s', '12.5 min', '3.2 h'."""
    if seconds < 120:
        return f"{seconds:.0f} s"
    if seconds < 2 * 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


# ============================================================
# HEAP (P1.3, P1.5)
# ============================================================


def resolve_max_heap(
    config: JVMHeapConfig | None,
    cli_max_heap_bytes: int | None,
    log_max_heap_bytes: int | None,
) -> tuple[int | None, str]:
    """Max heap in KB and where it came from (--max-heap > -Xmx > JVM startup log)."""
    if cli_max_heap_bytes:
        return cli_max_heap_bytes // 1024, "--max-heap"
    if config and config.max_heap_size_bytes:
        return config.max_heap_size_bytes // 1024, "-Xmx/MaxHeapSize (CommandLine flags)"
    if log_max_heap_bytes:
        return log_max_heap_bytes // 1024, "JVM startup log (unified gc,init/gc,heap)"
    return None, "committed heap (max heap unknown)"


def compute_heap_stats(events: list[GCEvent], max_heap_kb: int | None, source: str) -> HeapStats:
    """Peak before/after GC as % of max heap; events without heap data are excluded."""
    with_heap = [e for e in events if e.has_heap_data]
    if not with_heap:
        return HeapStats(max_heap_kb=max_heap_kb, max_heap_source=source)
    known = max_heap_kb is not None
    peak_before = max(e.heap_before_kb for e in with_heap)
    peak_after = max(e.heap_after_kb for e in with_heap)
    avg_after = mean(e.heap_after_kb for e in with_heap)
    if known:
        assert max_heap_kb is not None
        denominator = float(max_heap_kb)
    else:
        denominator = float(max(e.heap_total_kb for e in with_heap))

    def pct(value: float) -> float:
        return min(100.0, value / denominator * 100) if denominator else 0.0

    return HeapStats(
        events_with_heap_data=len(with_heap),
        max_heap_kb=max_heap_kb if known else int(denominator),
        max_heap_source=source,
        max_heap_known=known,
        peak_before_gc_kb=peak_before,
        peak_after_gc_kb=peak_after,
        avg_after_gc_kb=avg_after,
        peak_before_gc_pct=pct(peak_before),
        peak_after_gc_pct=pct(peak_after),
        avg_after_gc_pct=pct(avg_after),
        headroom_pct=100.0 - pct(peak_after),
    )


# ============================================================
# OLD-GEN FLOOR TREND (P1.1)
# ============================================================


def _mixed_cycle_ends(events: list[GCEvent]) -> list[GCEvent]:
    """Last Mixed pause of each run of consecutive G1 mixed collections."""
    ends: list[GCEvent] = []
    last_mixed: GCEvent | None = None
    for event in events:
        if event.gc_kind == "Mixed":
            last_mixed = event
        elif event.gc_kind in ("Young", "Full") and last_mixed is not None:
            ends.append(last_mixed)
            last_mixed = None
    if last_mixed is not None:
        ends.append(last_mixed)
    return ends


def _assessable(floor_events: list[GCEvent], thresholds: DiagnosticThresholds) -> bool:
    if len(floor_events) < thresholds.min_floor_count:
        return False
    span = (floor_events[-1].timestamp - floor_events[0].timestamp).total_seconds() / 3600
    return span >= thresholds.min_floor_span_hours


def compute_floor_trend(
    events: list[GCEvent],
    *,
    is_g1: bool,
    heap: HeapStats,
    thresholds: DiagnosticThresholds,
) -> FloorTrend:
    """Trend of occupancy right after collections that clean the old generation.

    Old gen is a sawtooth; its floors (after Full GCs, and for G1 after each mixed cycle)
    show the live set. A floor that keeps rising is the leak signal. Explicit Full GCs are
    valid floor measurements, so all Full GCs count here.
    """
    candidates: list[tuple[GCEvent, str]] = [
        (e, f"Full GC ({e.cause or 'cause not logged'})")
        for e in events
        if e.gc_kind == "Full" and e.has_heap_data
    ]
    if is_g1:
        candidates += [(e, "end of mixed cycle") for e in _mixed_cycle_ends(events)]
    candidates.sort(key=lambda pair: pair[0].timestamp)

    metric: Literal["old", "heap"] = "old"
    if not candidates or any(e.old_after_kb is None for e, _ in candidates):
        metric = "heap"
    if is_g1 and not _assessable([e for e, _ in candidates], thresholds):
        # Few or clustered mixed cycles: the heap right after Remark (end of marking) is the
        # best available approximation of the live set over time.
        remarks = [
            (e, "after Remark (approximate)")
            for e in events
            if e.gc_kind == "Remark" and e.has_heap_data
        ]
        if _assessable([e for e, _ in remarks], thresholds):
            candidates, metric = remarks, "heap"

    def value(event: GCEvent) -> int:
        if metric == "old" and event.old_after_kb is not None:
            return event.old_after_kb
        return event.heap_after_kb

    # Capacity for the % figures: generational collectors have a sized old gen; for G1 and
    # whole-heap floors the max heap is what the floor can grow into.
    capacity: int | None
    capacity_source: str
    old_totals = [e.old_total_kb for e, _ in candidates if e.old_total_kb]
    if metric == "old" and not is_g1 and old_totals:
        capacity, capacity_source = max(old_totals), "old generation capacity"
    elif heap.max_heap_kb:
        capacity, capacity_source = heap.max_heap_kb, heap.max_heap_source
    else:
        capacity, capacity_source = None, "unknown"

    floors = [
        FloorPoint(
            timestamp=e.timestamp,
            uptime_seconds=e.uptime_seconds,
            wall_clock=e.wall_clock,
            value_kb=value(e),
            pct_of_capacity=value(e) / capacity * 100 if capacity else None,
            source=source,
        )
        for e, source in candidates
    ]
    trend = FloorTrend(
        assessed=False,
        metric=metric,
        capacity_kb=capacity,
        capacity_source=capacity_source,
        floors=floors,
    )
    if not floors:
        trend.reason = "no Full GCs or completed mixed cycles in the window"
        return trend
    span_seconds = (floors[-1].timestamp - floors[0].timestamp).total_seconds()
    trend.span_hours = span_seconds / 3600
    trend.first_mb = floors[0].value_kb / 1024
    trend.last_mb = floors[-1].value_kb / 1024
    if (
        len(floors) < thresholds.min_floor_count
        or trend.span_hours < thresholds.min_floor_span_hours
    ):
        trend.reason = (
            f"{len(floors)} floor{'s' if len(floors) != 1 else ''} in "
            f"{format_duration(span_seconds)}; needs ≥ {thresholds.min_floor_count} "
            f"spanning ≥ {thresholds.min_floor_span_hours:g} h"
        )
        return trend
    xs = [(f.timestamp - floors[0].timestamp).total_seconds() / 3600 for f in floors]
    ys = [f.value_kb / 1024 for f in floors]
    fit = linear_fit(xs, ys)
    if fit is None:  # pragma: no cover - span check above guarantees spread
        trend.reason = "floors have no time spread"
        return trend
    slope, r_squared = fit
    trend.assessed = True
    trend.slope_mb_per_hour = slope
    trend.r_squared = r_squared
    if capacity:
        trend.slope_pct_per_hour = slope * 1024 / capacity * 100
    return trend


# ============================================================
# LEAK SCORE
# ============================================================


def calculate_leak_severity(summary: GCSummary, thresholds: DiagnosticThresholds) -> LeakSeverity:
    """Leak score (0-100) built on the floor trend; not assessed without floors."""
    trend = summary.floor_trend
    if not trend.floors:
        return LeakSeverity(
            score=0.0,
            severity_level="None",
            assessed=False,
            indicators=[f"Not assessed: {trend.reason or 'no post-collection floors'}"],
        )
    score = 0.0
    indicators: list[str] = []

    # Factor 1 (0-35): floor slope, as growth over the window relative to capacity
    if trend.assessed and trend.slope_mb_per_hour is not None:
        r2 = trend.r_squared or 0.0
        growth_pct = (trend.slope_pct_per_hour or 0.0) * trend.span_hours
        if trend.slope_mb_per_hour > 0 and r2 >= thresholds.min_floor_r_squared:
            points = (
                35.0
                if growth_pct > 20
                else 20.0
                if growth_pct > 10
                else 10.0
                if growth_pct > 5
                else 0.0
            )
            if points:
                score += points
                indicators.append(
                    f"Old-gen floor rising {trend.slope_mb_per_hour:+.1f} MB/h "
                    f"(+{growth_pct:.1f}% of capacity over {trend.span_hours:.1f} h, r²={r2:.2f})"
                )
    else:
        indicators.append(f"Floor trend not assessed: {trend.reason}")

    # Factor 2 (0-20): each Full GC reclaims less over time
    if summary.reclamation_declining:
        score += 20.0
        indicators.append("Memory reclaimed per Full GC is declining")

    # Factor 3 (0-15): heap-pressure Full GCs coming faster
    if summary.full_gc_accelerating:
        score += 15.0
        indicators.append("Heap-pressure Full GC frequency accelerating")

    # Factor 4 (0-20): latest floor close to capacity (live set fills the space)
    latest = trend.floors[-1].pct_of_capacity
    if latest is not None and latest > 90:
        score += 20.0
        indicators.append(f"Latest floor at {latest:.1f}% of capacity")
    elif latest is not None and latest > 80:
        score += 10.0
        indicators.append(f"Latest floor at {latest:.1f}% of capacity")

    # Factor 5 (0-10): little headroom after GC against the max heap
    headroom = summary.heap.headroom_pct
    if headroom < thresholds.heap_minimum_headroom_percentage:
        score += 10.0
        indicators.append(f"Only {headroom:.1f}% heap headroom after GC")
    elif headroom < 10:
        score += 5.0
        indicators.append(f"Only {headroom:.1f}% heap headroom after GC")

    score = min(score, 100.0)
    if score >= 80:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 40:
        level = "Medium"
    elif score >= 20:
        level = "Low"
    else:
        level = "None"
    return LeakSeverity(score=score, severity_level=level, indicators=indicators)


# ============================================================
# COLLECTOR METRICS
# ============================================================


def analyze_metaspace(events: list[GCEvent], metadata_full_gcs: int) -> MetaspaceAnalysis | None:
    """Metaspace usage, plus Full GCs that metaspace triggered."""
    metaspace_events = [
        e for e in events if e.metaspace_before_kb is not None and e.metaspace_after_kb is not None
    ]
    if not metaspace_events and not metadata_full_gcs:
        return None
    used_percentages = [
        e.metaspace_after_kb / e.metaspace_total_kb * 100
        for e in metaspace_events
        if e.metaspace_after_kb is not None and e.metaspace_total_kb
    ]
    growth_kb = 0
    if metaspace_events:
        growth_kb = (metaspace_events[-1].metaspace_after_kb or 0) - (
            metaspace_events[0].metaspace_after_kb or 0
        )

    warnings: list[str] = []
    if used_percentages and max(used_percentages) > 90:
        warnings.append(f"Metaspace usage peaked at {max(used_percentages):.1f}%")
    if growth_kb > 50 * 1024:
        warnings.append(f"Metaspace grew by {growth_kb // 1024}MB")
    if metadata_full_gcs:
        warnings.append(f"{metadata_full_gcs} Full GC(s) triggered by metaspace")

    return MetaspaceAnalysis(
        metaspace_events_count=len(metaspace_events),
        average_metaspace_used_percentage=mean(used_percentages) if used_percentages else 0.0,
        peak_metaspace_used_percentage=max(used_percentages) if used_percentages else 0.0,
        metaspace_growth_kb=growth_kb,
        metaspace_growing=growth_kb > 10 * 1024,
        metadata_full_gc_count=metadata_full_gcs,
        metaspace_warnings=warnings,
    )


def calculate_g1_metrics(events: list[GCEvent], runtime_hours: float | None) -> G1Metrics:
    """G1 mixed collections, humongous-triggered pauses and evacuation failures."""
    mixed = [e for e in events if e.gc_kind == "Mixed"]
    humongous = [e for e in events if e.humongous_detected]
    evacuation_failures = [e for e in events if e.evacuation_failed]
    to_space = [e for e in events if e.to_space_exhausted]
    warnings: list[str] = []
    if evacuation_failures:
        warnings.append(f"{len(evacuation_failures)} evacuation failure(s)")
    if len(humongous) > len(events) * 0.1:
        warnings.append("Over 10% of pauses triggered by humongous allocations")
    return G1Metrics(
        mixed_gc_count=len(mixed),
        mixed_gc_frequency_per_hour=len(mixed) / runtime_hours if runtime_hours else None,
        average_mixed_gc_pause_seconds=mean(e.pause_time_seconds for e in mixed) if mixed else 0.0,
        humongous_allocation_count=len(humongous),
        evacuation_failure_count=len(evacuation_failures),
        to_space_exhausted_count=len(to_space),
        # every completed G1 marking cycle has exactly one Remark pause
        concurrent_marking_cycles=sum(1 for e in events if e.gc_kind == "Remark"),
        g1_warnings=warnings,
    )


def calculate_cms_metrics(events: list[GCEvent], runtime_hours: float | None) -> CMSMetrics:
    """CMS cycles (= Initial Mark pauses) and the two CMS failure modes (P1.6)."""
    initial_marks = [e for e in events if e.gc_kind == "Initial Mark"]
    remarks = [e for e in events if e.gc_kind == "Remark"]
    return CMSMetrics(
        concurrent_cycles=len(initial_marks),
        cms_cycle_frequency_per_hour=len(initial_marks) / runtime_hours if runtime_hours else None,
        concurrent_mode_failures=sum(1 for e in events if e.concurrent_mode_failure),
        promotion_failures=sum(1 for e in events if e.promotion_failed),
        average_initial_mark_pause_seconds=(
            mean(e.pause_time_seconds for e in initial_marks) if initial_marks else 0.0
        ),
        average_remark_pause_seconds=mean(e.pause_time_seconds for e in remarks)
        if remarks
        else 0.0,
    )


def max_events_in_window(times: list[float], window_seconds: float) -> int:
    """Largest number of timestamps (sorted seconds) inside any window of that length."""
    best = 0
    start = 0
    for end, t in enumerate(times):
        while t - times[start] > window_seconds:
            start += 1
        best = max(best, end - start + 1)
    return best


def allocation_rate(events: list[GCEvent]) -> tuple[float | None, str | None]:
    """Allocation between consecutive GCs (P1.8), in MB/s, and the basis used.

    Allocated between GC n-1 and GC n = occupancy before GC n - occupancy after GC n-1.
    Young-generation sizes are preferred (old gen can shrink concurrently under CMS/G1);
    whole-heap sizes are the fallback.
    """
    young = [e for e in events if e.young_before_kb is not None and e.young_after_kb is not None]
    if len(young) >= 2:
        series, basis = young, "young generation"
        before = [e.young_before_kb or 0 for e in series]
        after = [e.young_after_kb or 0 for e in series]
    else:
        series = [e for e in events if e.has_heap_data]
        basis = "whole heap"
        before = [e.heap_before_kb for e in series]
        after = [e.heap_after_kb for e in series]
    if len(series) < 2:
        return None, None
    span = (series[-1].timestamp - series[0].timestamp).total_seconds()
    if span <= 0:
        return None, None
    allocated_kb = sum(max(0, before[i] - after[i - 1]) for i in range(1, len(series)))
    return allocated_kb / 1024 / span, basis


# ============================================================
# SUMMARY
# ============================================================


def build_comprehensive_summary(
    events: list[GCEvent],
    thresholds: DiagnosticThresholds,
    *,
    gc_type: str = "",
    jvm_heap_config: JVMHeapConfig | None = None,
    max_heap_bytes: int | None = None,
    max_heap_from_log_bytes: int | None = None,
) -> GCSummary:
    """Build the analysis summary for one window of events (sorted by time)."""
    events = sorted(events, key=lambda e: e.timestamp)
    by_kind: dict[str, list[GCEvent]] = {kind: [] for kind in GC_KINDS}
    for event in events:
        by_kind[event.gc_kind].append(event)
    full_events = by_kind["Full"]
    heap_full = [e for e in full_events if is_heap_pressure_full_gc(e)]

    # Window (P1.4)
    runtime_seconds = 0.0
    if len(events) >= 2:
        runtime_seconds = (events[-1].timestamp - events[0].timestamp).total_seconds()
    runtime_hours = runtime_seconds / 3600
    rates_reliable = runtime_hours >= thresholds.min_rate_window_hours and runtime_hours > 0
    rate_hours = runtime_hours if rates_reliable else None

    # Full GC causes (P1.2)
    cause_rows: dict[str, list[GCEvent]] = {}
    for event in full_events:
        cause_rows.setdefault(event.cause or "(cause not logged)", []).append(event)
    full_gc_causes = sorted(
        (
            FullGCCause(
                cause=cause,
                category=classify_full_gc_cause(None if cause.startswith("(") else cause),
                count=len(rows),
                total_pause_seconds=sum(e.pause_time_seconds for e in rows),
                max_pause_seconds=max(e.pause_time_seconds for e in rows),
            )
            for cause, rows in cause_rows.items()
        ),
        key=lambda c: (-c.count, c.cause),
    )
    explicit_count = sum(c.count for c in full_gc_causes if c.category == "explicit")
    metadata_count = sum(c.count for c in full_gc_causes if c.category == "metadata")
    causes_by_kind: dict[str, dict[str, int]] = {}
    for kind, kind_events in by_kind.items():
        if kind_events:
            counts = Counter(e.cause or "(cause not logged)" for e in kind_events)
            causes_by_kind[kind] = dict(counts.most_common())

    # Heap-pressure Full GC timing (P1.2, P1.7)
    intervals = [
        (heap_full[i].timestamp - heap_full[i - 1].timestamp).total_seconds() / 60
        for i in range(1, len(heap_full))
    ]
    full_gc_accelerating = False
    if len(intervals) >= 3:
        first_half = mean(intervals[: len(intervals) // 2])
        second_half = mean(intervals[len(intervals) // 2 :])
        full_gc_accelerating = second_half < first_half * thresholds.full_gc_acceleration_threshold
    max_streak = max_events_in_window(
        [(e.timestamp - events[0].timestamp).total_seconds() for e in heap_full],
        thresholds.full_gc_streak_window_seconds,
    )

    # Pauses
    all_pauses = [e.pause_time_seconds for e in events]
    overall = pause_stats(all_pauses)
    pauses_by_kind = {
        kind: pause_stats([e.pause_time_seconds for e in kind_events])
        for kind, kind_events in by_kind.items()
        if kind_events
    }
    total_gc_time = overall.total
    gc_overhead_pct = total_gc_time / runtime_seconds * 100 if runtime_seconds else 0.0

    # Heap vs max (P1.3, P1.5)
    max_heap_kb, max_heap_source = resolve_max_heap(
        jvm_heap_config, max_heap_bytes, max_heap_from_log_bytes
    )
    heap = compute_heap_stats(events, max_heap_kb, max_heap_source)

    # Old gen (sawtooth) and floors (P1.1)
    old = [e.old_used_percentage for e in events if e.old_used_percentage is not None]
    is_g1 = "G1" in gc_type
    floor_trend = compute_floor_trend(events, is_g1=is_g1, heap=heap, thresholds=thresholds)

    # Full GC effectiveness (all Full GCs: each measures the live set)
    reducing = growing = 0
    reclaimed: list[float] = []
    post_full_pcts: list[float] = []
    for event in full_events:
        if event.old_before_kb is not None and event.old_after_kb is not None:
            delta = event.old_after_kb - event.old_before_kb
            reducing += delta < 0
            growing += delta > 0
            if delta < 0:
                reclaimed.append(-delta)
            if event.old_used_percentage is not None:
                post_full_pcts.append(event.old_used_percentage)
    reclamation_declining = False
    if len(reclaimed) >= 4:
        first_half_r = mean(reclaimed[: len(reclaimed) // 2])
        second_half_r = mean(reclaimed[len(reclaimed) // 2 :])
        reclamation_declining = (
            second_half_r < first_half_r * thresholds.reclamation_decline_threshold
        )

    # Promotion and allocation (P1.8)
    promotions = [
        e.old_after_kb - e.old_before_kb
        for e in by_kind["Young"]
        if e.old_before_kb is not None
        and e.old_after_kb is not None
        and e.old_after_kb > e.old_before_kb
    ]
    alloc_rate, alloc_basis = allocation_rate([e for e in events if e.gc_kind != "Remark"])

    # Early / middle / late
    period_stats: dict[str, PeriodStatistics] = {}
    if len(events) >= 3 and runtime_seconds > 0:
        third = (events[-1].timestamp - events[0].timestamp) / 3
        early_end = events[0].timestamp + third
        middle_end = early_end + third
        buckets = {
            "early": [e for e in events if e.timestamp < early_end],
            "middle": [e for e in events if early_end <= e.timestamp < middle_end],
            "late": [e for e in events if e.timestamp >= middle_end],
        }
        for name, bucket in buckets.items():
            bucket_old = [
                e.old_used_percentage for e in bucket if e.old_used_percentage is not None
            ]
            period_stats[name] = PeriodStatistics(
                average_old_gen_percentage=mean(bucket_old) if bucket_old else None,
                full_gc_count=sum(1 for e in bucket if e.gc_kind == "Full"),
            )

    summary = GCSummary(
        runtime_seconds=runtime_seconds,
        runtime_hours=runtime_hours,
        first_timestamp=events[0].timestamp if events else None,
        last_timestamp=events[-1].timestamp if events else None,
        wall_clock=all(e.wall_clock for e in events),
        rates_reliable=rates_reliable,
        total_event_count=len(events),
        counts_by_kind={k: len(v) for k, v in by_kind.items() if v},
        young_gc_count=len(by_kind["Young"]),
        mixed_gc_count=len(by_kind["Mixed"]),
        full_gc_count=len(full_events),
        initial_mark_count=len(by_kind["Initial Mark"]),
        remark_gc_count=len(by_kind["Remark"]),
        cleanup_gc_count=len(by_kind["Cleanup"]),
        heap_full_gc_count=len(heap_full),
        explicit_full_gc_count=explicit_count,
        metadata_full_gc_count=metadata_count,
        full_gc_causes=full_gc_causes,
        causes_by_kind=causes_by_kind,
        young_gc_per_hour=len(by_kind["Young"]) / rate_hours if rate_hours else None,
        full_gc_per_hour=len(heap_full) / rate_hours if rate_hours else None,
        avg_full_gc_interval_min=mean(intervals) if intervals else None,
        min_full_gc_interval_min=min(intervals) if intervals else None,
        time_to_first_full_gc_hours=(
            (heap_full[0].timestamp - events[0].timestamp).total_seconds() / 3600
            if heap_full
            else None
        ),
        full_gc_accelerating=full_gc_accelerating,
        max_full_gc_streak=max_streak,
        total_gc_time_sec=total_gc_time,
        gc_overhead_pct=gc_overhead_pct,
        throughput_pct=max(0.0, 100 - gc_overhead_pct),
        overall_pauses=overall,
        pauses_by_kind=pauses_by_kind,
        pauses_over_1s=sum(1 for p in all_pauses if p > 1.0),
        pauses_over_5s=sum(1 for p in all_pauses if p > 5.0),
        pauses_over_30s=sum(1 for p in all_pauses if p > 30.0),
        pauses_over_60s=sum(1 for p in all_pauses if p > 60.0),
        heap=heap,
        peak_old_pct=max(old) if old else None,
        avg_old_pct=mean(old) if old else None,
        floor_trend=floor_trend,
        full_gc_reducing=reducing,
        full_gc_growing=growing,
        avg_post_full_gc_pct=mean(post_full_pcts) if post_full_pcts else None,
        avg_reclaimed_kb=mean(reclaimed) if reclaimed else 0.0,
        reclamation_declining=reclamation_declining,
        avg_promotion_kb=mean(promotions) if promotions else 0.0,
        allocation_rate_mb_sec=alloc_rate,
        allocation_basis=alloc_basis,
        period_stats=period_stats,
        leak_severity=LeakSeverity(score=0.0, severity_level="None"),
        jvm_heap_config=jvm_heap_config,
    )
    summary.leak_severity = calculate_leak_severity(summary, thresholds)
    summary.metaspace_analysis = analyze_metaspace(events, metadata_count)
    if is_g1:
        summary.g1_metrics = calculate_g1_metrics(events, rate_hours)
    if "CMS" in gc_type or summary.initial_mark_count:
        summary.cms_metrics = calculate_cms_metrics(events, rate_hours)
    summary.warnings, summary.data_notes = build_warnings_and_notes(summary, thresholds)
    return summary


def build_warnings_and_notes(
    summary: GCSummary, thresholds: DiagnosticThresholds
) -> tuple[list[str], list[str]]:
    """Health warnings ("CRITICAL:"/"WARNING:" prefixed) and data-quality notes."""
    warnings: list[str] = []
    notes: list[str] = []
    heap = summary.heap
    t = thresholds

    # ---- data notes
    if not summary.rates_reliable:
        notes.append(
            f"Log window is {format_duration(summary.runtime_seconds)}: per-hour rates and "
            f"rate-based warnings need at least {t.min_rate_window_hours * 60:.0f} min of log, "
            "so counts are shown instead"
        )
    if not summary.wall_clock:
        notes.append("Log has no wall-clock time: times are JVM uptime (pass --jvm-start)")
    if not heap.max_heap_known and heap.events_with_heap_data:
        notes.append(
            "Max heap (-Xmx) not found in the log: heap percentages are of the committed heap "
            "and can overstate pressure (pass --max-heap)"
        )
    without_heap = summary.total_event_count - heap.events_with_heap_data
    if without_heap:
        notes.append(
            f"{without_heap} pause(s) logged without heap sizes are counted in pause "
            "statistics but excluded from heap statistics"
        )
    if summary.peak_old_pct is None:
        notes.append("Old-generation sizes are not in this log; old-gen statistics are limited")
    if not summary.floor_trend.assessed:
        notes.append(f"Old-gen floor trend not assessed: {summary.floor_trend.reason}")
    if summary.explicit_full_gc_count:
        notes.append(
            f"{summary.explicit_full_gc_count} explicit Full GC(s) (System.gc() and similar) "
            "are reported but excluded from Full GC rates, streaks and leak scoring"
        )

    # ---- health warnings
    if heap.events_with_heap_data:
        basis = "max heap" if heap.max_heap_known else "committed heap"
        peak = heap.peak_after_gc_pct
        if peak > t.heap_critical_percentage:
            warnings.append(
                f"CRITICAL: Heap after GC peaked at {peak:.1f}% of {basis} "
                f"(threshold {t.heap_critical_percentage:.0f}%) - OOM risk"
            )
        elif peak > t.heap_warning_percentage:
            warnings.append(
                f"WARNING: Heap after GC peaked at {peak:.1f}% of {basis} "
                f"(threshold {t.heap_warning_percentage:.0f}%) - high memory pressure"
            )
    if summary.full_gc_per_hour is not None:
        if summary.full_gc_per_hour > t.full_gc_critical_per_hour:
            warnings.append(
                f"CRITICAL: {summary.full_gc_per_hour:.1f} heap-pressure Full GCs per hour "
                f"(threshold {t.full_gc_critical_per_hour:.0f})"
            )
        elif summary.full_gc_per_hour > t.full_gc_warning_per_hour:
            warnings.append(
                f"WARNING: {summary.full_gc_per_hour:.1f} heap-pressure Full GCs per hour "
                f"(threshold {t.full_gc_warning_per_hour:.0f})"
            )
    if summary.gc_overhead_pct > t.gc_overhead_critical_percentage:
        warnings.append(
            f"CRITICAL: GC overhead {summary.gc_overhead_pct:.1f}% "
            f"(threshold {t.gc_overhead_critical_percentage:.0f}%)"
        )
    elif summary.gc_overhead_pct > t.gc_overhead_warning_percentage:
        warnings.append(
            f"WARNING: GC overhead {summary.gc_overhead_pct:.1f}% "
            f"(threshold {t.gc_overhead_warning_percentage:.0f}%)"
        )
    p99 = summary.overall_pauses.p99
    if p99 > t.pause_critical_seconds:
        warnings.append(
            f"CRITICAL: P99 pause {p99:.3f}s (threshold {t.pause_critical_seconds:.0f}s)"
        )
    elif p99 > t.pause_warning_seconds:
        warnings.append(f"WARNING: P99 pause {p99:.3f}s (threshold {t.pause_warning_seconds:.0f}s)")
    if summary.max_full_gc_streak >= t.full_gc_streak_count:
        warnings.append(
            f"CRITICAL: {summary.max_full_gc_streak} heap-pressure Full GCs within "
            f"{t.full_gc_streak_window_seconds / 60:.0f} minutes - memory thrashing"
        )
    if summary.full_gc_accelerating:
        warnings.append("CRITICAL: Heap-pressure Full GC frequency is accelerating")
    if summary.reclamation_declining:
        warnings.append("CRITICAL: Each Full GC reclaims less memory over time")
    if summary.metadata_full_gc_count:
        warnings.append(
            f"WARNING: {summary.metadata_full_gc_count} Full GC(s) triggered by metaspace "
            "(Metadata GC Threshold) - review MetaspaceSize/MaxMetaspaceSize, not -Xmx"
        )
    if summary.g1_metrics and summary.g1_metrics.evacuation_failure_count:
        warnings.append(
            f"WARNING: {summary.g1_metrics.evacuation_failure_count} G1 evacuation failure(s) "
            "(to-space exhausted) - heap too full to copy live objects"
        )
    if summary.cms_metrics:
        if summary.cms_metrics.concurrent_mode_failures:
            warnings.append(
                f"CRITICAL: {summary.cms_metrics.concurrent_mode_failures} CMS concurrent mode "
                "failure(s) - old gen filled before the concurrent cycle finished"
            )
        if summary.cms_metrics.promotion_failures:
            warnings.append(
                f"CRITICAL: {summary.cms_metrics.promotion_failures} promotion failure(s) - "
                "old gen too full or fragmented to accept promoted objects"
            )
    return warnings, notes
