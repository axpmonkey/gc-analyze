"""Diagnostics: summary statistics, leak scoring and collector metrics."""

from __future__ import annotations

from bisect import bisect_right
from collections import Counter
from datetime import datetime, timedelta
from statistics import mean, median
from typing import Literal

from .models import (
    GC_KINDS,
    CMSMetrics,
    ConcurrentStats,
    CpuStats,
    DiagnosticThresholds,
    FloorPoint,
    FloorStep,
    FloorTrend,
    FullGCCategory,
    FullGCCause,
    G1Metrics,
    GCEvent,
    GCSummary,
    HealthWarning,
    HeapStats,
    JVMEnvironment,
    JVMHeapConfig,
    LeakSeverity,
    MetaspaceAnalysis,
    PauseShareWindow,
    PauseStats,
    PeriodStatistics,
    SafepointStats,
    SideRecord,
    SurvivorOverflow,
    TimelineBucket,
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


def format_time(timestamp: datetime, wall_clock: bool, uptime: float | None) -> str:
    """Wall-clock ISO time, or JVM uptime when the log has no wall clock."""
    if wall_clock:
        return timestamp.isoformat(timespec="milliseconds")
    return f"uptime {uptime:.3f}s" if uptime is not None else "n/a"


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


# Pauses that reclaim memory. Remark, Cleanup and CMS Initial Mark log the occupancy at that
# moment, not the result of a collection, so they say nothing about what survives a GC.
COLLECTING_KINDS: frozenset[str] = frozenset({"Young", "Mixed", "Full"})


def compute_heap_stats(events: list[GCEvent], max_heap_kb: int | None, source: str) -> HeapStats:
    """Peak before/after GC as % of max heap; events without heap data are excluded.

    "After GC" figures come from collecting pauses only (see ``COLLECTING_KINDS``).
    """
    with_heap = [e for e in events if e.has_heap_data]
    if not with_heap:
        return HeapStats(max_heap_kb=max_heap_kb, max_heap_source=source)
    known = max_heap_kb is not None
    collecting = [e for e in with_heap if e.gc_kind in COLLECTING_KINDS]
    after_events = collecting or with_heap
    peak_before = max(e.heap_before_kb for e in with_heap)
    peak_after = max(e.heap_after_kb for e in after_events)
    avg_after = mean(e.heap_after_kb for e in after_events)
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
        collecting_events_with_heap_data=len(collecting),
        exceeds_max_heap=known and peak_before > denominator,
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


def _in_warmup(event: GCEvent, thresholds: DiagnosticThresholds) -> bool:
    """True for a pause during JVM start-up (only knowable when the log has uptime)."""
    return event.uptime_seconds is not None and event.uptime_seconds < thresholds.warmup_seconds


def format_mb_per_hour(mb_per_hour: float) -> str:
    """'+12.5 MB/h' / '+187.7 GB/h'."""
    if abs(mb_per_hour) >= 1024:
        return f"{mb_per_hour / 1024:+.1f} GB/h"
    return f"{mb_per_hour:+.1f} MB/h"


def find_floor_step(
    floors: list[FloorPoint], capacity_kb: int | None, thresholds: DiagnosticThresholds
) -> FloorStep | None:
    """Largest jump to a floor well above everything before it, if there is one.

    A live set that multiplies between two collections is a retention event (a huge request,
    a batch load, a cache filling at once), which a slope over the whole window misdescribes.
    """
    best: FloorStep | None = None
    best_rise = 0
    for index in range(1, len(floors)):
        before, after = floors[index - 1], floors[index]
        baseline = median(f.value_kb for f in floors[:index])
        rise = after.value_kb - before.value_kb
        if after.value_kb < thresholds.floor_step_factor * baseline or rise <= best_rise:
            continue
        if capacity_kb and rise / capacity_kb * 100 < thresholds.floor_step_min_capacity_percentage:
            continue
        best, best_rise = FloorStep(before=before, after=after), rise
    return best


def _assessable(floor_events: list[GCEvent], thresholds: DiagnosticThresholds) -> bool:
    floor_events = [e for e in floor_events if not _in_warmup(e, thresholds)]
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
    show the live set. A floor that keeps rising means the live set is growing (a leak, a
    cache filling, or more load). Explicit Full GCs are valid floor measurements, so all Full
    GCs count here.

    Floors from JVM start-up are listed but left out of the trend, and a line is only fitted
    when floors are spread over the span: two clusters always fit a line well.
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
            warmup=_in_warmup(e, thresholds),
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
    all_floors, floors = floors, trend.trend_floors
    warmup_minutes = thresholds.warmup_seconds / 60
    if not floors:
        trend.reason = (
            f"all {len(all_floors)} floor{'s are' if len(all_floors) != 1 else ' is'} from JVM "
            f"start-up (first {warmup_minutes:.0f} min of uptime)"
        )
        return trend
    trend.step_change = find_floor_step(floors, capacity, thresholds)
    span_seconds = (floors[-1].timestamp - floors[0].timestamp).total_seconds()
    trend.span_hours = span_seconds / 3600
    trend.first_mb = floors[0].value_kb / 1024
    trend.last_mb = floors[-1].value_kb / 1024
    skipped = len(all_floors) - len(floors)
    left_out = (
        f" ({skipped} start-up floor{'s' if skipped != 1 else ''} left out)" if skipped else ""
    )
    if (
        len(floors) < thresholds.min_floor_count
        or trend.span_hours < thresholds.min_floor_span_hours
    ):
        trend.reason = (
            f"{len(floors)} floor{'s' if len(floors) != 1 else ''} in "
            f"{format_duration(span_seconds)}{left_out}; needs ≥ {thresholds.min_floor_count} "
            f"spanning ≥ {thresholds.min_floor_span_hours:g} h"
        )
        return trend
    xs = [(f.timestamp - floors[0].timestamp).total_seconds() / 3600 for f in floors]
    if not any(trend.span_hours / 3 <= x <= trend.span_hours * 2 / 3 for x in xs):
        trend.reason = (
            f"the {len(floors)} floors{left_out} sit in two clusters with none in the middle "
            "third of their span; a line through two clusters is not a trend"
        )
        return trend
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


def cleaned_floors(trend: FloorTrend) -> list[FloorPoint]:
    """Floors that show what the application holds: measured, with a known capacity.

    Start-up floors are left out when later ones exist: a full heap during start-up is a
    transient, not the state the application runs in.
    """
    usable = [
        f
        for f in trend.floors
        if f.pct_of_capacity is not None and not f.source.startswith("after Remark")
    ]
    return [f for f in usable if not f.warmup] or usable


def describe_floor_step(trend: FloorTrend) -> str:
    """'Live set jumped from 6.64 GB (at T1) to 245.29 GB (at T2)'; '' without a step."""
    step = trend.step_change
    if step is None:
        return ""

    def size(kb: int) -> str:
        return f"{kb / 1048576:.2f} GB" if kb >= 1048576 else f"{kb / 1024:.0f} MB"

    def when(point: FloorPoint) -> str:
        return format_time(point.timestamp, point.wall_clock, point.uptime_seconds)

    return (
        f"Live set jumped from {size(step.before.value_kb)} (after the collection at "
        f"{when(step.before)}) to {size(step.after.value_kb)} (at {when(step.after)})"
    )


def calculate_leak_severity(summary: GCSummary, thresholds: DiagnosticThresholds) -> LeakSeverity:
    """Leak score (0-100) built on the floor trend; not assessed without floors."""
    trend = summary.floor_trend
    floors = trend.trend_floors
    if not floors:
        return LeakSeverity(
            score=0.0,
            severity_level="None",
            assessed=False,
            indicators=[f"Not assessed: {trend.reason or 'no post-collection floors'}"],
        )
    score = 0.0
    indicators: list[str] = []
    if trend.step_change is not None:
        indicators.append(
            f"{describe_floor_step(trend)} - sudden retention rather than gradual growth "
            "(not scored as a leak)"
        )

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
                    f"Old-gen floor rising {format_mb_per_hour(trend.slope_mb_per_hour)} "
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
    latest = floors[-1].pct_of_capacity
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


def analyze_metaspace(
    events: list[GCEvent],
    metadata_full_gcs: int,
    *,
    max_metaspace_bytes: int | None = None,
    warmup_seconds: float = 600.0,
) -> MetaspaceAnalysis | None:
    """Metaspace used sizes, growth after warm-up, and Full GCs that metaspace triggered.

    The bracketed figure on a metaspace log line is reserved (Java 8, JDK 11) or committed
    (JDK 17+) space, not a limit, so a percentage is only computed against
    -XX:MaxMetaspaceSize when that flag is known. Class loading during start-up is left out
    of the growth figure.
    """
    metaspace_events = [
        e for e in events if e.metaspace_before_kb is not None and e.metaspace_after_kb is not None
    ]
    if not metaspace_events and not metadata_full_gcs:
        return None
    used = [e.metaspace_after_kb or 0 for e in metaspace_events]
    limit_kb = max_metaspace_bytes // 1024 if max_metaspace_bytes else None
    used_percentages = [value / limit_kb * 100 for value in used] if limit_kb else []

    def past_warmup(event: GCEvent) -> bool:
        if event.uptime_seconds is not None:
            return event.uptime_seconds >= warmup_seconds
        elapsed = (event.timestamp - metaspace_events[0].timestamp).total_seconds()
        return elapsed >= warmup_seconds

    steady = [e.metaspace_after_kb or 0 for e in metaspace_events if past_warmup(e)]
    growth_measured = len(steady) >= 2
    growth_kb = steady[-1] - steady[0] if growth_measured else 0

    warnings: list[str] = []
    if used_percentages and max(used_percentages) > 90:
        warnings.append(f"Metaspace peaked at {max(used_percentages):.1f}% of -XX:MaxMetaspaceSize")
    if growth_kb > 50 * 1024:
        warnings.append(
            f"Metaspace grew by {growth_kb // 1024} MB after warm-up "
            f"({steady[0] // 1024} MB to {steady[-1] // 1024} MB)"
        )

    return MetaspaceAnalysis(
        metaspace_events_count=len(metaspace_events),
        average_metaspace_used_percentage=mean(used_percentages) if used_percentages else 0.0,
        peak_metaspace_used_percentage=max(used_percentages) if used_percentages else 0.0,
        metaspace_growth_kb=growth_kb,
        metaspace_growing=growth_kb > 10 * 1024,
        metadata_full_gc_count=metadata_full_gcs,
        metaspace_warnings=warnings,
        first_used_kb=used[0] if used else 0,
        peak_used_kb=max(used) if used else 0,
        last_used_kb=used[-1] if used else 0,
        max_metaspace_kb=limit_kb,
        limit_known=limit_kb is not None,
        growth_measured=growth_measured,
    )


# A share of very few pauses says nothing; below this count no humongous warning is raised
MIN_HUMONGOUS_PAUSES_FOR_WARNING = 5


def calculate_g1_metrics(events: list[GCEvent], runtime_hours: float | None) -> G1Metrics:
    """G1 mixed collections, humongous-triggered pauses and evacuation failures."""
    mixed = [e for e in events if e.gc_kind == "Mixed"]
    humongous = [e for e in events if e.humongous_detected]
    evacuation_failures = [e for e in events if e.evacuation_failed]
    to_space = [e for e in events if e.to_space_exhausted]
    # Evacuation failures get their own health warning; this list holds the rest.
    warnings: list[str] = []
    if len(humongous) >= MIN_HUMONGOUS_PAUSES_FOR_WARNING and len(humongous) > len(events) * 0.1:
        warnings.append(
            f"{len(humongous)} of {len(events)} pauses "
            f"({len(humongous) / len(events) * 100:.0f}%) were triggered by humongous "
            "allocations (objects of half a G1 region or more)"
        )
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


def max_back_to_back(starts: list[float], ends: list[float], window_seconds: float) -> int:
    """Most pauses in a row where the last starts within the window of the first one ending.

    Measuring from the end of the first pause keeps long pauses countable: three 150 s Full
    GCs 30 s apart are back-to-back even though their starts are 180 s apart.
    """
    best = 0
    first = 0
    for last, start in enumerate(starts):
        while start - ends[first] > window_seconds:
            first += 1
        best = max(best, last - first + 1)
    return best


def merge_intervals(intervals: list[tuple[float, float]]) -> list[tuple[float, float]]:
    """Sorted, non-overlapping copy of (start, end) intervals."""
    merged: list[tuple[float, float]] = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def worst_pause_share(
    intervals: list[tuple[float, float]], window_seconds: float
) -> tuple[float, float] | None:
    """(paused seconds, window start) of the window holding the most pause time.

    ``intervals`` are merged (start, end) pause times in seconds. Returns None when the
    pauses span less than one window. The maximum is always reached with the window starting
    at a pause start or ending at a pause end, so only those positions are tried.
    """
    if not intervals:
        return None
    span_start, span_end = intervals[0][0], intervals[-1][1]
    if span_end - span_start < window_seconds:
        return None
    starts = [start for start, _ in intervals]
    cumulative = [0.0]
    for start, end in intervals:
        cumulative.append(cumulative[-1] + (end - start))

    def paused_before(moment: float) -> float:
        count = bisect_right(starts, moment)
        if count == 0:
            return 0.0
        start, end = intervals[count - 1]
        return cumulative[count - 1] + min(end, moment) - start

    best_paused, best_start = -1.0, span_start
    latest_start = span_end - window_seconds
    for start, end in intervals:
        for candidate in (start, end - window_seconds):
            window_start = min(max(candidate, span_start), latest_start)
            paused = paused_before(window_start + window_seconds) - paused_before(window_start)
            if paused > best_paused:
                best_paused, best_start = paused, window_start
    return best_paused, best_start


PAUSE_SHARE_WINDOWS_SECONDS: tuple[float, ...] = (60.0, 300.0, 900.0)
# Timeline slice lengths; the shortest one that keeps the table within TIMELINE_MAX_ROWS is used
TIMELINE_BUCKET_SECONDS: tuple[float, ...] = (60.0, 300.0, 900.0, 3600.0, 10800.0, 21600.0, 86400.0)
TIMELINE_MAX_ROWS = 48


def timeline_bucket_length(span_seconds: float) -> float:
    """Slice length for a window of this many seconds."""
    for length in TIMELINE_BUCKET_SECONDS:
        if span_seconds / length <= TIMELINE_MAX_ROWS:
            return length
    days_per_bucket = -(-span_seconds // (TIMELINE_MAX_ROWS * 86400.0))  # ceiling
    return days_per_bucket * 86400.0


def build_timeline(
    events: list[GCEvent],
    event_starts: list[float],
    pause_spans: list[tuple[float, float]],
    origin: datetime,
    heap_capacity_kb: int | None,
) -> tuple[list[TimelineBucket], float]:
    """Cut the window into equal slices: pauses, time paused, longest pause, Full GCs, heap.

    ``event_starts`` are each event's pause start and ``pause_spans`` the merged, clipped
    pause intervals, both in seconds from ``origin``. A pause counts in the slice it starts
    in; its paused time is split across the slices it covers.
    """
    if not pause_spans or pause_spans[-1][1] <= pause_spans[0][0]:
        return [], 0.0
    span_start, span_end = pause_spans[0][0], pause_spans[-1][1]
    length = timeline_bucket_length(span_end - span_start)
    count = max(1, int(-(-(span_end - span_start) // length)))
    first_uptime = events[0].uptime_seconds
    wall_clock = all(e.wall_clock for e in events)
    buckets: list[TimelineBucket] = []
    for index in range(count):
        offset = span_start + index * length
        buckets.append(
            TimelineBucket(
                start=origin + timedelta(seconds=offset),
                wall_clock=wall_clock,
                uptime_seconds=first_uptime + offset if first_uptime is not None else None,
                length_seconds=min(length, span_end - offset),
            )
        )

    def bucket_of(moment: float) -> TimelineBucket:
        return buckets[min(count - 1, max(0, int((moment - span_start) // length)))]

    for start, end in pause_spans:
        index = min(count - 1, int((start - span_start) // length))
        while index < count and span_start + index * length < end:
            slice_start = span_start + index * length
            overlap = min(end, slice_start + length) - max(start, slice_start)
            buckets[index].paused_seconds += max(0.0, overlap)
            index += 1
    for event, start in zip(events, event_starts, strict=True):
        bucket = bucket_of(start)
        bucket.pause_count += 1
        bucket.longest_pause_seconds = max(bucket.longest_pause_seconds, event.pause_time_seconds)
        bucket.full_gc_count += event.gc_kind == "Full"
        if event.has_heap_data and event.gc_kind in COLLECTING_KINDS:
            bucket.heap_after_kb = event.heap_after_kb
    for bucket in buckets:
        if bucket.length_seconds > 0:
            bucket.paused_percentage = min(
                100.0, bucket.paused_seconds / bucket.length_seconds * 100
            )
        if bucket.heap_after_kb is not None and heap_capacity_kb:
            bucket.heap_after_percentage = min(100.0, bucket.heap_after_kb / heap_capacity_kb * 100)
    return buckets, length


# Pauses shorter than this are not judged on CPU split: the log resolves 10 ms
MIN_JUDGED_REAL_SECONDS = 0.1
HIGH_SYS_SHARE_OF_USER = 0.2
OFF_CPU_REAL_FACTOR = 1.5
SLOW_SAFEPOINT_STOPPING_SECONDS = 1.0


def compute_cpu_stats(events: list[GCEvent]) -> CpuStats | None:
    """Where pause time went: collecting (user), the kernel (sys), or waiting (real >> CPU)."""
    timed = [
        e
        for e in events
        if e.cpu_user_seconds is not None
        and e.cpu_sys_seconds is not None
        and e.cpu_real_seconds is not None
    ]
    if not timed:
        return None

    def describe(event: GCEvent) -> str:
        return (
            f"user={event.cpu_user_seconds:.2f} sys={event.cpu_sys_seconds:.2f} "
            f"real={event.cpu_real_seconds:.2f} at "
            f"{format_time(event.timestamp, event.wall_clock, event.uptime_seconds)}"
        )

    judged = [e for e in timed if (e.cpu_real_seconds or 0.0) >= MIN_JUDGED_REAL_SECONDS]
    high_sys = [
        e
        for e in judged
        if (e.cpu_sys_seconds or 0.0) > HIGH_SYS_SHARE_OF_USER * (e.cpu_user_seconds or 0.0)
    ]
    off_cpu = [
        e
        for e in judged
        if (e.cpu_real_seconds or 0.0)
        > OFF_CPU_REAL_FACTOR * ((e.cpu_user_seconds or 0.0) + (e.cpu_sys_seconds or 0.0))
    ]
    return CpuStats(
        pauses_with_cpu_times=len(timed),
        judged_pauses=len(judged),
        high_sys_count=len(high_sys),
        worst_high_sys=describe(max(high_sys, key=lambda e: e.cpu_sys_seconds or 0.0))
        if high_sys
        else "",
        off_cpu_count=len(off_cpu),
        worst_off_cpu=describe(
            max(
                off_cpu,
                key=lambda e: (
                    (e.cpu_real_seconds or 0.0)
                    - (e.cpu_user_seconds or 0.0)
                    - (e.cpu_sys_seconds or 0.0)
                ),
            )
        )
        if off_cpu
        else "",
    )


def find_survivor_overflow(
    events: list[GCEvent], thresholds: DiagnosticThresholds
) -> tuple[SurvivorOverflow | None, bool]:
    """Young collections that filled the survivor space and promoted the rest.

    Returns the overflow (None below the minimum count) and whether survivor occupancy was
    logged at all. A survivor space that is full right after a young collection could not
    hold everything that survived, so the excess went straight to the old generation.
    """
    young = [e for e in events if e.gc_kind == "Young" and e.survivor_used_percentage is not None]
    overflowing = [
        e
        for e in young
        if (e.survivor_used_percentage or 0.0) >= thresholds.survivor_full_percentage
        and e.old_before_kb is not None
        and e.old_after_kb is not None
        and e.old_after_kb > e.old_before_kb
    ]
    if len(overflowing) < thresholds.survivor_overflow_min_count:
        return None, bool(young)
    first, last = overflowing[0], overflowing[-1]
    return (
        SurvivorOverflow(
            count=len(overflowing),
            young_gc_count=len(young),
            first_when=format_time(first.timestamp, first.wall_clock, first.uptime_seconds),
            last_when=format_time(last.timestamp, last.wall_clock, last.uptime_seconds),
            survivor_capacity_kb=max(e.survivor_capacity_kb or 0 for e in overflowing),
            promoted_kb=sum((e.old_after_kb or 0) - (e.old_before_kb or 0) for e in overflowing),
        ),
        True,
    )


def compute_concurrent_stats(
    records: list[SideRecord], runtime_seconds: float
) -> ConcurrentStats | None:
    """Time the collector worked alongside the application (not counted in pause overhead)."""
    concurrent = [r for r in records if r.kind == "concurrent"]
    if not concurrent:
        return None
    total = sum(r.seconds for r in concurrent)
    label = Counter(r.label for r in concurrent).most_common(1)[0][0]
    return ConcurrentStats(
        label=label,
        cycles=len(concurrent),
        total_seconds=total,
        share_percentage=min(100.0, total / runtime_seconds * 100) if runtime_seconds else None,
        average_seconds=total / len(concurrent),
        longest_seconds=max(r.seconds for r in concurrent),
    )


def compute_safepoint_stats(records: list[SideRecord]) -> SafepointStats | None:
    """Application-stopped time, and safepoints that were slow to stop the threads."""
    stops = [r for r in records if r.kind == "safepoint"]
    if not stops:
        return None
    longest = max(stops, key=lambda r: r.seconds)
    slow = [r for r in stops if (r.stopping_seconds or 0.0) >= SLOW_SAFEPOINT_STOPPING_SECONDS]
    slowest = max(stops, key=lambda r: r.stopping_seconds or 0.0)
    return SafepointStats(
        count=len(stops),
        total_stopped_seconds=sum(r.seconds for r in stops),
        longest_stopped_seconds=longest.seconds,
        longest_stopped_when=longest.when,
        slow_to_stop_count=len(slow),
        longest_stopping_seconds=slowest.stopping_seconds or 0.0,
        longest_stopping_when=slowest.when if slowest.stopping_seconds else "",
    )


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
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    side_records: list[SideRecord] | None = None,
    environment: JVMEnvironment | None = None,
) -> GCSummary:
    """Build the analysis summary for one window of events (sorted by time).

    ``window_start``/``window_end`` are the --start/--end bounds: pauses that straddle them
    only count for the part inside the window.
    """
    events = sorted(events, key=lambda e: e.timestamp)
    by_kind: dict[str, list[GCEvent]] = {kind: [] for kind in GC_KINDS}
    for event in events:
        by_kind[event.gc_kind].append(event)
    full_events = by_kind["Full"]
    heap_full = [e for e in full_events if is_heap_pressure_full_gc(e)]

    # Window (P1.4): from the start of the first pause to the end of the last one, clipped
    # to --start/--end. Offsets are seconds from the first event's timestamp; a pause's own
    # length is added as a float so sums stay exact (datetime only resolves microseconds).
    origin = events[0].timestamp if events else None
    lower = (window_start - origin).total_seconds() if window_start and origin else None
    upper = (window_end - origin).total_seconds() if window_end and origin else None
    clipped: list[tuple[float, float]] = []
    event_starts: list[float] = []
    run_spans: dict[int, tuple[float, float]] = {}  # per JVM run: first pause start, last end
    time_in_gc = 0.0
    for event in events:
        assert origin is not None
        stamp = (event.timestamp - origin).total_seconds()
        pause = event.pause_time_seconds
        start, end = (stamp - pause, stamp) if event.stamp_at_pause_end else (stamp, stamp + pause)
        event_starts.append(start)
        cut = 0.0
        if lower is not None and start < lower:
            cut += min(pause, lower - start)
        if upper is not None and end > upper:
            cut += min(pause, end - upper)
        time_in_gc += max(0.0, pause - cut)
        clipped_start = start if lower is None else max(start, lower)
        clipped_end = end if upper is None else min(end, upper)
        if clipped_end >= clipped_start:
            clipped.append((clipped_start, clipped_end))
            low, high = run_spans.get(event.segment, (clipped_start, clipped_end))
            run_spans[event.segment] = (min(low, clipped_start), max(high, clipped_end))
    wall_clock = all(e.wall_clock for e in events)
    jvm_run_count = max(1, len(run_spans))
    # Without wall-clock time every JVM run starts again at uptime 0, so runs analysed
    # together overlap on the time axis: worst stretches and the timeline cannot be placed.
    placeable = jvm_run_count == 1 or wall_clock
    pause_spans = merge_intervals(clipped) if placeable else []
    # The window is the time the JVM was running: downtime between runs is not part of it.
    runtime_seconds = 0.0
    if len(events) >= 2:
        runtime_seconds = sum(high - low for low, high in run_spans.values())
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
    max_streak = max_back_to_back(
        [(e.pause_start - events[0].timestamp).total_seconds() for e in heap_full],
        [(e.pause_end - events[0].timestamp).total_seconds() for e in heap_full],
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
    total_gc_time = time_in_gc
    gc_overhead_pct = min(100.0, total_gc_time / runtime_seconds * 100) if runtime_seconds else 0.0

    # Worst stretches: a whole-window average hides an incident at the end of a long log
    worst_pause_shares: list[PauseShareWindow] = []
    for window_seconds in PAUSE_SHARE_WINDOWS_SECONDS:
        worst = worst_pause_share(pause_spans, window_seconds)
        if worst is None or origin is None:
            continue
        paused, offset = worst
        first_uptime = events[0].uptime_seconds
        worst_pause_shares.append(
            PauseShareWindow(
                window_seconds=window_seconds,
                paused_seconds=paused,
                share_percentage=min(100.0, paused / window_seconds * 100),
                window_start=origin + timedelta(seconds=offset),
                wall_clock=wall_clock,
                uptime_seconds=first_uptime + offset if first_uptime is not None else None,
            )
        )

    # Heap vs max (P1.3, P1.5)
    max_heap_kb, max_heap_source = resolve_max_heap(
        jvm_heap_config, max_heap_bytes, max_heap_from_log_bytes
    )
    heap = compute_heap_stats(events, max_heap_kb, max_heap_source)
    timeline: list[TimelineBucket] = []
    timeline_bucket_seconds = 0.0
    if origin is not None and runtime_seconds > 0 and pause_spans:
        timeline, timeline_bucket_seconds = build_timeline(
            events, event_starts, pause_spans, origin, heap.max_heap_kb
        )

    # Old gen (sawtooth) and floors (P1.1). One denominator for every old-gen percentage:
    # the sized old generation for generational collectors; for G1, which has no fixed old
    # generation, the max heap (or the committed heap when the max is unknown).
    is_g1 = "G1" in gc_type
    old_capacity_kb = heap.max_heap_kb if is_g1 and heap.max_heap_known else None
    if old_capacity_kb:
        old_pct_basis = "max heap"
    else:
        old_pct_basis = "committed heap" if is_g1 else "old generation capacity"

    def old_pct(event: GCEvent) -> float | None:
        if old_capacity_kb and event.old_after_kb is not None:
            return min(100.0, event.old_after_kb / old_capacity_kb * 100)
        return event.old_used_percentage

    old = [pct for pct in (old_pct(e) for e in events) if pct is not None]
    floor_trend = compute_floor_trend(events, is_g1=is_g1, heap=heap, thresholds=thresholds)

    # Full GC effectiveness on the whole heap. Old-gen deltas mislead: a Full GC moves the
    # surviving young objects into the old generation, so old gen can grow while the
    # collection frees memory.
    reducing = growing = 0
    reclaimed: list[float] = []
    reclaimed_pcts: list[float] = []
    heap_reclaimed: list[float] = []
    heap_reclaimed_pcts: list[float] = []
    post_full_pcts: list[float] = []
    ineffective_full_gcs = 0
    for event in full_events:
        post_pct = old_pct(event)
        if post_pct is not None:
            post_full_pcts.append(post_pct)
        if not event.has_heap_data:
            continue
        freed = event.heap_before_kb - event.heap_after_kb
        reducing += freed > 0
        growing += freed < 0
        freed_kb = float(max(0, freed))
        freed_pct = freed_kb / event.heap_before_kb * 100 if event.heap_before_kb else 0.0
        reclaimed.append(freed_kb)
        reclaimed_pcts.append(freed_pct)
        if is_heap_pressure_full_gc(event):
            heap_reclaimed.append(freed_kb)
            heap_reclaimed_pcts.append(freed_pct)
            # Freeing little is only a problem when what is left nearly fills the space
            capacity_kb = heap.max_heap_kb or event.heap_total_kb
            still_used_pct = (
                post_pct if post_pct is not None else event.heap_after_kb / capacity_kb * 100
            )
            if (
                freed_pct < thresholds.ineffective_full_gc_reclaim_percentage
                and still_used_pct > thresholds.heap_warning_percentage
            ):
                ineffective_full_gcs += 1
    reclamation_declining = False
    if len(heap_reclaimed) >= 4:
        first_half_r = mean(heap_reclaimed[: len(heap_reclaimed) // 2])
        second_half_r = mean(heap_reclaimed[len(heap_reclaimed) // 2 :])
        reclamation_declining = (
            second_half_r < first_half_r * thresholds.reclamation_decline_threshold
        )

    # Promotion and allocation (P1.8). Every young GC with old-gen sizes counts, including
    # the ones that promoted nothing.
    promotions = [
        max(0, e.old_after_kb - e.old_before_kb)
        for e in by_kind["Young"]
        if e.old_before_kb is not None and e.old_after_kb is not None
    ]
    total_promoted_kb = sum(promotions)
    alloc_rate, alloc_basis = allocation_rate([e for e in events if e.gc_kind != "Remark"])
    if alloc_rate is not None and jvm_run_count > 1:
        # the rate was taken over first-to-last pause, which includes downtime between runs
        elapsed = (events[-1].timestamp - events[0].timestamp).total_seconds()
        alloc_rate = (
            alloc_rate * elapsed / runtime_seconds if wall_clock and runtime_seconds else None
        )
    if is_g1 and alloc_basis == "young generation":
        # humongous objects are allocated straight into the old generation's regions
        alloc_basis = "young generation; excludes humongous allocations"

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
            bucket_old = [pct for pct in (old_pct(e) for e in bucket) if pct is not None]
            period_stats[name] = PeriodStatistics(
                average_old_gen_percentage=mean(bucket_old) if bucket_old else None,
                full_gc_count=sum(1 for e in bucket if e.gc_kind == "Full"),
            )

    summary = GCSummary(
        runtime_seconds=runtime_seconds,
        runtime_hours=runtime_hours,
        first_timestamp=events[0].timestamp if events else None,
        last_timestamp=events[-1].timestamp if events else None,
        wall_clock=wall_clock,
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
        overhead_measured=runtime_seconds > 0,
        worst_pause_shares=worst_pause_shares,
        timeline=timeline,
        timeline_bucket_seconds=timeline_bucket_seconds,
        overall_pauses=overall,
        pauses_by_kind=pauses_by_kind,
        pauses_over_1s=sum(1 for p in all_pauses if p > 1.0),
        pauses_over_5s=sum(1 for p in all_pauses if p > 5.0),
        pauses_over_30s=sum(1 for p in all_pauses if p > 30.0),
        pauses_over_60s=sum(1 for p in all_pauses if p > 60.0),
        heap=heap,
        peak_old_pct=max(old) if old else None,
        avg_old_pct=mean(old) if old else None,
        old_pct_basis=old_pct_basis,
        old_pct_capacity_kb=old_capacity_kb,
        floor_trend=floor_trend,
        full_gc_reducing=reducing,
        full_gc_growing=growing,
        avg_post_full_gc_pct=mean(post_full_pcts) if post_full_pcts else None,
        avg_reclaimed_kb=mean(reclaimed) if reclaimed else 0.0,
        reclamation_declining=reclamation_declining,
        avg_full_gc_reclaimed_pct=mean(reclaimed_pcts) if reclaimed_pcts else None,
        heap_full_gc_reclaimed_pcts=heap_reclaimed_pcts,
        ineffective_full_gc_count=ineffective_full_gcs,
        avg_promotion_kb=mean(promotions) if promotions else 0.0,
        total_promoted_kb=total_promoted_kb,
        promotion_rate_mb_sec=(
            total_promoted_kb / 1024 / runtime_seconds if promotions and runtime_seconds else None
        ),
        allocation_rate_mb_sec=alloc_rate,
        allocation_basis=alloc_basis,
        period_stats=period_stats,
        leak_severity=LeakSeverity(score=0.0, severity_level="None"),
        jvm_heap_config=jvm_heap_config,
    )
    summary.leak_severity = calculate_leak_severity(summary, thresholds)
    summary.metaspace_analysis = analyze_metaspace(
        events,
        metadata_count,
        max_metaspace_bytes=jvm_heap_config.max_metaspace_size_bytes if jvm_heap_config else None,
        warmup_seconds=thresholds.warmup_seconds,
    )
    if is_g1:
        summary.g1_metrics = calculate_g1_metrics(events, rate_hours)
    if "CMS" in gc_type or summary.initial_mark_count:
        summary.cms_metrics = calculate_cms_metrics(events, rate_hours)
    summary.cpu_stats = compute_cpu_stats(events)
    summary.survivor_overflow, summary.survivor_occupancy_logged = find_survivor_overflow(
        events, thresholds
    )
    summary.unified_log = any(e.stamp_at_pause_end for e in events)
    summary.jvm_run_count = jvm_run_count
    summary.has_uptime = any(e.uptime_seconds is not None for e in events)
    summary.is_g1 = is_g1
    summary.concurrent_stats = compute_concurrent_stats(side_records or [], runtime_seconds)
    summary.safepoint_stats = compute_safepoint_stats(side_records or [])
    summary.environment = environment
    summary.health_warnings, summary.data_notes = build_health_warnings(summary, thresholds)
    summary.warnings = [warning.line for warning in summary.health_warnings]
    return summary


def not_assessed_notes(summary: GCSummary) -> list[str]:
    """What this log could not show, and the logging option that would show it."""
    if not summary.total_event_count:
        return []
    notes: list[str] = []
    if summary.cpu_stats is None:
        option = (
            "the gc+cpu tag, which -Xlog:gc* includes"
            if summary.unified_log
            else "-XX:+PrintGCDetails, which adds [Times: user= sys= real=]"
        )
        notes.append(
            "Not assessed: kernel time and waiting during pauses (no CPU times in the log; "
            f"needs {option})"
        )
    if summary.safepoint_stats is None:
        option = "-Xlog:safepoint" if summary.unified_log else "-XX:+PrintGCApplicationStoppedTime"
        notes.append(
            "Not assessed: time to stop the application threads (no application-stopped lines "
            f"this tool reads; needs {option})"
        )
    if not summary.has_uptime:
        notes.append(
            "Not assessed: JVM start-up (the log has no uptime), so floors and metaspace growth "
            "may include start-up; needs -XX:+PrintGCTimeStamps or the uptime decorator"
        )
    if not summary.is_g1 and not summary.unified_log and not summary.survivor_occupancy_logged:
        notes.append(
            "Not assessed: survivor overflow / premature promotion (no survivor occupancy in "
            "the log; needs -XX:+PrintHeapAtGC)"
        )
    if (summary.is_g1 or summary.cms_metrics is not None) and summary.concurrent_stats is None:
        notes.append(
            "Not assessed: concurrent collector work (no concurrent cycle or phase durations "
            "in the log)"
        )
    return notes


def build_warnings_and_notes(
    summary: GCSummary, thresholds: DiagnosticThresholds
) -> tuple[list[str], list[str]]:
    """Health warnings as "CRITICAL: ..."/"WARNING: ..." lines, and data-quality notes."""
    coded, notes = build_health_warnings(summary, thresholds)
    return [warning.line for warning in coded], notes


def build_health_warnings(
    summary: GCSummary, thresholds: DiagnosticThresholds
) -> tuple[list[HealthWarning], list[str]]:
    """Health warnings, each with the code of its condition, and data-quality notes."""
    warnings: list[HealthWarning] = []
    notes: list[str] = []

    def warn(code: str, line: str) -> None:
        level, _, text = line.partition(": ")
        assert level in ("CRITICAL", "WARNING"), line
        warnings.append(
            HealthWarning(
                code=code, level="CRITICAL" if level == "CRITICAL" else "WARNING", text=text
            )
        )

    heap = summary.heap
    t = thresholds

    # ---- data notes
    if not summary.rates_reliable:
        notes.append(
            f"Log window is {format_duration(summary.runtime_seconds)}: per-hour rates and "
            f"rate-based warnings need at least {t.min_rate_window_hours * 60:.0f} min of log, "
            "so counts are shown instead"
        )
    if summary.total_event_count and not summary.overhead_measured:
        notes.append(
            "The window holds a single pause: there is no elapsed time to compute GC overhead "
            "or rates from"
        )
    if not summary.wall_clock:
        notes.append("Log has no wall-clock time: times are JVM uptime (pass --jvm-start)")
    if heap.exceeds_max_heap:
        notes.append(
            f"Heap occupancy in the log ({heap.peak_before_gc_kb // 1024} MB) is above the max "
            f"heap used for percentages ({(heap.max_heap_kb or 0) // 1024} MB from "
            f"{heap.max_heap_source}): that value does not belong to this log, and heap "
            "percentages are capped at 100%"
        )
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
    if summary.jvm_run_count > 1:
        notes.append(
            f"{summary.jvm_run_count} JVM runs are analysed together: downtime between runs is "
            "left out of the window, overhead and rates, but trends and floors mix the runs"
            + (
                ""
                if summary.wall_clock
                else "; without wall-clock time the runs overlap, so the timeline and worst "
                "stretches are not shown"
            )
        )
    notes.extend(not_assessed_notes(summary))

    # ---- health warnings
    # Memory pressure is judged right after a collection that cleans the old generation (a
    # Full GC, or the end of a G1 mixed cycle): that is what the application really holds.
    # Occupancy after a young GC still includes old-generation garbage, so it is only the
    # fallback when the log has no such collection.
    cleaned = cleaned_floors(summary.floor_trend)
    basis = "max heap" if heap.max_heap_known else "committed heap"
    if cleaned:
        trend = summary.floor_trend
        fullest = max(cleaned, key=lambda f: f.pct_of_capacity or 0.0)
        peak = fullest.pct_of_capacity or 0.0
        subject = "Old generation" if trend.metric == "old" else "Heap"
        of = basis if trend.capacity_source != "old generation capacity" else "its capacity"
        where = (
            f"{subject} was {peak:.1f}% of {of} right after {fullest.source} at "
            f"{format_time(fullest.timestamp, fullest.wall_clock, fullest.uptime_seconds)}"
        )
        if peak > t.heap_critical_percentage:
            warn(
                "heap_occupancy",
                f"CRITICAL: {where} (threshold {t.heap_critical_percentage:.0f}%) - "
                "live data nearly fills it; OOM risk",
            )
        elif peak > t.heap_warning_percentage:
            warn(
                "heap_occupancy",
                f"WARNING: {where} (threshold {t.heap_warning_percentage:.0f}%) - "
                "high memory pressure",
            )
    elif heap.events_with_heap_data:
        peak = heap.peak_after_gc_pct
        if peak > t.heap_critical_percentage:
            warn(
                "heap_occupancy",
                f"CRITICAL: Heap after GC peaked at {peak:.1f}% of {basis} "
                f"(threshold {t.heap_critical_percentage:.0f}%) - OOM risk",
            )
        elif peak > t.heap_warning_percentage:
            warn(
                "heap_occupancy",
                f"WARNING: Heap after GC peaked at {peak:.1f}% of {basis} "
                f"(threshold {t.heap_warning_percentage:.0f}%) - high memory pressure",
            )
    five_minutes = next((w for w in summary.worst_pause_shares if w.window_seconds == 300.0), None)
    if five_minutes is not None:
        began = format_time(
            five_minutes.window_start, five_minutes.wall_clock, five_minutes.uptime_seconds
        )
        share = (
            f"the application was paused for {five_minutes.share_percentage:.1f}% of the worst "
            f"5 minutes ({five_minutes.paused_seconds:.0f} s of 300 s, starting {began})"
        )
        if five_minutes.share_percentage > t.pause_share_critical_percentage:
            warn(
                "pause_share",
                f"CRITICAL: {share} (threshold {t.pause_share_critical_percentage:.0f}%)",
            )
        elif five_minutes.share_percentage > t.pause_share_warning_percentage:
            warn(
                "pause_share",
                f"WARNING: {share} (threshold {t.pause_share_warning_percentage:.0f}%)",
            )
    if summary.floor_trend.step_change is not None:
        warn("live_set_step", f"WARNING: {describe_floor_step(summary.floor_trend)}")
    if summary.ineffective_full_gc_count:
        level = "CRITICAL" if summary.ineffective_full_gc_count >= 2 else "WARNING"
        warn(
            "ineffective_full_gc",
            f"{level}: {summary.ineffective_full_gc_count} of {summary.heap_full_gc_count} "
            "heap-pressure Full GCs freed less than "
            f"{t.ineffective_full_gc_reclaim_percentage:.0f}% of the heap and left it more than "
            f"{t.heap_warning_percentage:.0f}% full - live data fills the heap",
        )
    if summary.full_gc_per_hour is not None:
        if summary.full_gc_per_hour > t.full_gc_critical_per_hour:
            warn(
                "full_gc_rate",
                f"CRITICAL: {summary.full_gc_per_hour:.1f} heap-pressure Full GCs per hour "
                f"(threshold {t.full_gc_critical_per_hour:.0f})",
            )
        elif summary.full_gc_per_hour > t.full_gc_warning_per_hour:
            warn(
                "full_gc_rate",
                f"WARNING: {summary.full_gc_per_hour:.1f} heap-pressure Full GCs per hour "
                f"(threshold {t.full_gc_warning_per_hour:.0f})",
            )
    if summary.gc_overhead_pct > t.gc_overhead_critical_percentage:
        warn(
            "gc_overhead",
            f"CRITICAL: GC overhead {summary.gc_overhead_pct:.1f}% "
            f"(threshold {t.gc_overhead_critical_percentage:.0f}%)",
        )
    elif summary.gc_overhead_pct > t.gc_overhead_warning_percentage:
        warn(
            "gc_overhead",
            f"WARNING: GC overhead {summary.gc_overhead_pct:.1f}% "
            f"(threshold {t.gc_overhead_warning_percentage:.0f}%)",
        )
    p99 = summary.overall_pauses.p99
    if p99 > t.pause_critical_seconds:
        warn(
            "p99_pause",
            f"CRITICAL: P99 pause {p99:.3f}s (threshold {t.pause_critical_seconds:.0f}s)",
        )
    elif p99 > t.pause_warning_seconds:
        warn(
            "p99_pause", f"WARNING: P99 pause {p99:.3f}s (threshold {t.pause_warning_seconds:.0f}s)"
        )
    if summary.max_full_gc_streak >= t.full_gc_streak_count:
        warn(
            "full_gc_streak",
            f"CRITICAL: {summary.max_full_gc_streak} heap-pressure Full GCs within "
            f"{t.full_gc_streak_window_seconds / 60:.0f} minutes - memory thrashing",
        )
    if summary.full_gc_accelerating:
        warn("full_gc_accelerating", "CRITICAL: Heap-pressure Full GC frequency is accelerating")
    if summary.reclamation_declining:
        warn("reclamation_declining", "CRITICAL: Each Full GC reclaims less memory over time")
    if summary.metadata_full_gc_count:
        warn(
            "metaspace_full_gc",
            f"WARNING: {summary.metadata_full_gc_count} Full GC(s) triggered by metaspace "
            "(Metadata GC Threshold) - review MetaspaceSize/MaxMetaspaceSize, not -Xmx",
        )
    if summary.g1_metrics and summary.g1_metrics.evacuation_failure_count:
        warn(
            "g1_evacuation_failure",
            f"WARNING: {summary.g1_metrics.evacuation_failure_count} G1 evacuation failure(s) "
            "(to-space exhausted) - heap too full to copy live objects",
        )
    cpu = summary.cpu_stats
    # a handful of odd pauses is noise; a pattern is not
    if cpu and cpu.high_sys_count >= 3 and cpu.high_sys_count >= 0.05 * cpu.judged_pauses:
        warn(
            "cpu_kernel",
            f"WARNING: {cpu.high_sys_count} of {cpu.judged_pauses} pauses of 0.1 s or more spent "
            f"over 20% of their CPU time in the kernel (worst: {cpu.worst_high_sys}) - an "
            "operating-system memory cost, not collector work",
        )
    if cpu and cpu.off_cpu_count >= 3 and cpu.off_cpu_count >= 0.05 * cpu.judged_pauses:
        warn(
            "cpu_waiting",
            f"WARNING: {cpu.off_cpu_count} of {cpu.judged_pauses} pauses of 0.1 s or more took "
            f"far longer than the CPU time they used (worst: {cpu.worst_off_cpu}) - the collector "
            "was waiting (swapping, I/O or CPU contention), not working",
        )
    concurrent = summary.concurrent_stats
    if concurrent and (concurrent.share_percentage or 0.0) >= t.concurrent_share_warning_percentage:
        warn(
            "concurrent_share",
            f"WARNING: {concurrent.label} ran for {concurrent.share_percentage:.1f}% of the "
            f"window ({concurrent.cycles} cycles) - the collector is marking almost "
            "continuously, a CPU cost that pause overhead does not show",
        )
    stops = summary.safepoint_stats
    if stops and stops.slow_to_stop_count:
        warn(
            "safepoint_slow",
            f"WARNING: {stops.slow_to_stop_count} safepoint(s) needed 1 s or more just to stop "
            f"the application threads (longest {stops.longest_stopping_seconds:.1f} s at "
            f"{stops.longest_stopping_when}) - the application was frozen for longer than the "
            "GC pause times show",
        )
    env = summary.environment
    if (
        env
        and env.physical_memory_kb
        and heap.max_heap_known
        and heap.max_heap_kb
        and heap.max_heap_kb > env.physical_memory_kb
    ):
        warn(
            "heap_exceeds_physical",
            f"WARNING: max heap ({heap.max_heap_kb // 1024} MB) is larger than the host's "
            f"physical memory ({env.physical_memory_kb // 1024} MB) - the heap can only "
            "fill by swapping",
        )
    if env and env.swap_total_kb and env.swap_free_kb is not None:
        swap_used_kb = env.swap_total_kb - env.swap_free_kb
        if swap_used_kb > 0:
            notes.append(
                f"The host was already using {swap_used_kb // 1024} MB of swap when the JVM "
                "started: GC pauses on a swapping host are unpredictable"
            )
    overflow = summary.survivor_overflow
    if overflow is not None:
        warn(
            "survivor_overflow",
            f"WARNING: {overflow.count} of {overflow.young_gc_count} young collections left the "
            f"survivor space full and promoted {overflow.promoted_kb / 1048576:.1f} GB straight "
            f"into the old generation ({overflow.first_when} to {overflow.last_when})",
        )
    if summary.g1_metrics:
        for text in summary.g1_metrics.g1_warnings:
            warn("g1_humongous", f"WARNING: {text}")
    if summary.metaspace_analysis:
        for text in summary.metaspace_analysis.metaspace_warnings:
            warn("metaspace_usage", f"WARNING: {text}")
    if summary.cms_metrics:
        if summary.cms_metrics.concurrent_mode_failures:
            warn(
                "cms_concurrent_mode_failure",
                f"CRITICAL: {summary.cms_metrics.concurrent_mode_failures} CMS concurrent mode "
                "failure(s) - old gen filled before the concurrent cycle finished",
            )
        if summary.cms_metrics.promotion_failures:
            warn(
                "cms_promotion_failure",
                f"CRITICAL: {summary.cms_metrics.promotion_failures} promotion failure(s) - "
                "old gen too full or fragmented to accept promoted objects",
            )
    return warnings, notes
