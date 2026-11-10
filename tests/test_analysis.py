"""Analysis rules (P1): causes, windows, heap vs max, floors, leak score, allocation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from gc_analyze.analysis import (
    allocation_rate,
    build_comprehensive_summary,
    calculate_cms_metrics,
    classify_full_gc_cause,
    compute_floor_trend,
    compute_heap_stats,
    format_duration,
    linear_fit,
    max_events_in_window,
    percentile_sorted,
    resolve_max_heap,
)
from gc_analyze.models import DiagnosticThresholds, GCEvent, HeapStats, JVMHeapConfig

from .support import approx

T0 = datetime(2026, 1, 1, tzinfo=UTC)
MB = 1024


def ev(minutes: float, kind: str = "Young", pause: float = 0.01, **fields: Any) -> GCEvent:
    """Synthetic event `minutes` after T0."""
    values: dict[str, Any] = {
        "timestamp": T0 + timedelta(minutes=minutes),
        "uptime_seconds": minutes * 60,
        "gc_kind": kind,
        "pause_time_seconds": pause,
        "heap_before_kb": 500 * MB,
        "heap_after_kb": 300 * MB,
        "heap_total_kb": 1000 * MB,
        "heap_used_percentage": 30.0,
    }
    values.update(fields)
    return GCEvent(**values)


def full(
    minutes: float, old_after_mb: float, cause: str = "Allocation Failure", **f: Any
) -> GCEvent:
    return ev(
        minutes,
        "Full",
        1.0,
        cause=cause,
        old_before_kb=int(old_after_mb * MB) + 100 * MB,
        old_after_kb=int(old_after_mb * MB),
        old_total_kb=800 * MB,
        **f,
    )


TH = DiagnosticThresholds()


# ---------------------------------------------------------------- helpers


@pytest.mark.parametrize(
    ("cause", "category"),
    [
        ("System.gc()", "explicit"),
        ("Heap Inspection Initiated GC", "explicit"),
        ("Heap Dump Initiated GC", "explicit"),
        ("Metadata GC Threshold", "metadata"),
        ("Last ditch collection", "metadata"),
        ("Allocation Failure", "heap"),
        ("Ergonomics", "heap"),
        (None, "heap"),
    ],
)
def test_classify_full_gc_cause(cause: str | None, category: str) -> None:
    assert classify_full_gc_cause(cause) == category


def test_small_helpers() -> None:
    assert percentile_sorted([], 99) == 0.0
    assert percentile_sorted([1.0], 50) == 1.0
    assert percentile_sorted([1.0, 2.0, 3.0], 50) == 2.0
    assert linear_fit([1.0, 1.0], [1.0, 2.0]) is None
    assert linear_fit([0.0, 1.0], [5.0, 5.0]) == (0.0, 1.0)
    assert format_duration(30) == "30 s"
    assert format_duration(600) == "10.0 min"
    assert format_duration(4 * 3600) == "4.0 h"
    assert max_events_in_window([0, 100, 200, 1000], 300) == 3
    assert max_events_in_window([], 300) == 0


def test_resolve_max_heap_priority() -> None:
    config = JVMHeapConfig(max_heap_size_bytes=2 * 1024**3)
    assert resolve_max_heap(config, 4 * 1024**3, 1024**3) == (4 * 1024**2, "--max-heap")
    assert resolve_max_heap(config, None, 1024**3)[0] == 2 * 1024**2
    assert resolve_max_heap(None, None, 1024**3)[1].startswith("JVM startup log")
    assert resolve_max_heap(None, None, None) == (None, "committed heap (max heap unknown)")


# ---------------------------------------------------------------- heap (P1.3, P1.5)


def test_heap_stats_against_max_heap_and_committed() -> None:
    events = [
        ev(0, heap_before_kb=1000 * MB, heap_after_kb=400 * MB, heap_total_kb=1024 * MB),
        ev(1, "Remark", has_heap_data=False, heap_before_kb=0, heap_after_kb=0, heap_total_kb=0),
    ]
    with_max = compute_heap_stats(events, 2048 * MB, "-Xmx")
    assert with_max.events_with_heap_data == 1  # Remark without heap data excluded
    assert with_max.peak_before_gc_pct == approx(1000 / 2048 * 100)
    assert with_max.peak_after_gc_pct == approx(400 / 2048 * 100)
    assert with_max.max_heap_known
    committed = compute_heap_stats(events, None, "committed heap (max heap unknown)")
    assert not committed.max_heap_known
    assert committed.peak_before_gc_pct == approx(1000 / 1024 * 100)
    empty = compute_heap_stats([events[1]], None, "x")
    assert empty.events_with_heap_data == 0


# ---------------------------------------------------------------- windows & rates (P1.4)


def test_short_window_has_no_rates_and_no_rate_warnings() -> None:
    events = [ev(0), full(1, 100), ev(2)]
    summary = build_comprehensive_summary(events, TH, gc_type="Parallel GC")
    assert not summary.rates_reliable
    assert summary.full_gc_per_hour is None
    assert summary.young_gc_per_hour is None
    assert not any("per hour" in w for w in summary.warnings)
    assert any("per-hour rates" in n for n in summary.data_notes)


def test_long_window_has_rates() -> None:
    events = [ev(0), full(30, 100), full(60, 100), ev(90)]
    summary = build_comprehensive_summary(events, TH, gc_type="Parallel GC")
    assert summary.rates_reliable
    assert summary.full_gc_per_hour == approx(2 / 1.5)
    assert any(w.startswith("WARNING:") and "Full GCs per hour" in w for w in summary.warnings)


def test_min_rate_window_is_configurable() -> None:
    events = [ev(0), ev(10)]
    th = DiagnosticThresholds(min_rate_window_hours=0.1)
    assert build_comprehensive_summary(events, th).young_gc_per_hour == approx(12.0)


# ---------------------------------------------------------------- causes (P1.2, P1.7)


def test_explicit_and_metadata_full_gcs_excluded_from_rates_and_streaks() -> None:
    events = (
        [ev(0)]
        + [full(m, 100, "System.gc()") for m in (60, 61, 62, 63)]
        + [
            full(120, 100, "Metadata GC Threshold"),
            ev(180),
        ]
    )
    summary = build_comprehensive_summary(events, TH, gc_type="Parallel GC")
    assert summary.full_gc_count == 5
    assert (summary.heap_full_gc_count, summary.explicit_full_gc_count) == (0, 4)
    assert summary.metadata_full_gc_count == 1
    assert summary.full_gc_per_hour == 0.0
    assert summary.max_full_gc_streak == 0
    assert not any("within 5 minutes" in w for w in summary.warnings)
    assert any("triggered by metaspace" in w for w in summary.warnings)
    assert any("explicit Full GC" in n for n in summary.data_notes)
    assert summary.metaspace_analysis is not None
    assert summary.metaspace_analysis.metadata_full_gc_count == 1
    causes = {c.cause: (c.category, c.count) for c in summary.full_gc_causes}
    assert causes == {"System.gc()": ("explicit", 4), "Metadata GC Threshold": ("metadata", 1)}


def test_streak_needs_three_heap_full_gcs_in_five_minutes() -> None:
    two = [ev(0), full(10, 100), full(12, 100), ev(100)]
    assert build_comprehensive_summary(two, TH).max_full_gc_streak == 2
    assert not any("within 5 minutes" in w for w in build_comprehensive_summary(two, TH).warnings)
    three = [ev(0), full(10, 100), full(12, 100), full(14.5, 100), ev(100)]
    summary = build_comprehensive_summary(three, TH)
    assert summary.max_full_gc_streak == 3
    assert any(
        w.startswith("CRITICAL: 3 heap-pressure Full GCs within 5") for w in summary.warnings
    )


def test_acceleration_uses_heap_full_gcs() -> None:
    minutes = [0, 60, 110, 140, 150, 155]
    events = [full(m, 100) for m in minutes]
    summary = build_comprehensive_summary(events, TH)
    assert summary.full_gc_accelerating
    assert any("accelerating" in w for w in summary.warnings)


def test_cause_not_logged() -> None:
    events = [ev(0), ev(1, "Full", 1.0, cause=None)]
    summary = build_comprehensive_summary(events, TH)
    assert summary.full_gc_causes[0].cause == "(cause not logged)"
    assert summary.full_gc_causes[0].category == "heap"


# ---------------------------------------------------------------- floors (P1.1)


def test_floor_trend_known_slope() -> None:
    # floors 100, 150, 200, 250 MB at 0, 1, 2, 3 h; young GCs in between are not floors
    events = [full(h * 60, 100 + 50 * h) for h in range(4)] + [ev(30, old_after_kb=900 * MB)]
    events.sort(key=lambda e: e.timestamp)
    trend = compute_floor_trend(events, is_g1=False, heap=HeapStats(), thresholds=TH)
    assert trend.assessed
    assert trend.metric == "old"
    assert trend.slope_mb_per_hour == approx(50.0)
    assert trend.r_squared == approx(1.0)
    assert trend.capacity_kb == 800 * MB  # generational: old-gen capacity
    assert trend.slope_pct_per_hour == approx(50 / 800 * 100)


def test_floor_trend_not_assessed_reasons() -> None:
    none = compute_floor_trend([ev(0)], is_g1=False, heap=HeapStats(), thresholds=TH)
    assert not none.assessed
    assert none.reason == "no Full GCs or completed mixed cycles in the window"
    short = compute_floor_trend(
        [full(0, 1), full(1, 2), full(2, 3)], is_g1=False, heap=HeapStats(), thresholds=TH
    )
    assert not short.assessed
    assert short.reason is not None and short.reason.startswith("3 floors in 2.0 min")


def test_floor_metric_falls_back_to_heap_without_old_sizes() -> None:
    events = [ev(h * 60, "Full", 1.0, heap_after_kb=(100 + h) * MB) for h in range(3)]
    heap = HeapStats(max_heap_kb=2000 * MB, max_heap_known=True, max_heap_source="-Xmx")
    trend = compute_floor_trend(events, is_g1=False, heap=heap, thresholds=TH)
    assert trend.metric == "heap"
    assert trend.capacity_kb == 2000 * MB
    assert [f.value_kb for f in trend.floors] == [100 * MB, 101 * MB, 102 * MB]


def test_g1_floors_are_full_gcs_and_mixed_cycle_ends() -> None:
    events = [
        ev(0, "Mixed", old_after_kb=500 * MB),
        ev(1, "Mixed", old_after_kb=400 * MB),  # end of first mixed run
        ev(2, "Young", old_after_kb=450 * MB),
        ev(60, "Mixed", old_after_kb=420 * MB),  # end of second run (end of log)
    ]
    heap = HeapStats(max_heap_kb=1000 * MB, max_heap_known=True, max_heap_source="-Xmx")
    trend = compute_floor_trend(events, is_g1=True, heap=heap, thresholds=TH)
    assert [f.value_kb // MB for f in trend.floors] == [400, 420]
    assert {f.source for f in trend.floors} == {"end of mixed cycle"}


def test_g1_remark_fallback_when_mixed_floors_unusable() -> None:
    remarks = [ev(h * 60, "Remark", heap_after_kb=(300 + 10 * h) * MB) for h in range(4)]
    events = [ev(0.5, "Mixed", old_after_kb=200 * MB), *remarks]
    events.sort(key=lambda e: e.timestamp)
    trend = compute_floor_trend(events, is_g1=True, heap=HeapStats(), thresholds=TH)
    assert trend.assessed
    assert trend.metric == "heap"
    assert trend.floors[0].source == "after Remark (approximate)"
    assert trend.slope_mb_per_hour == approx(10.0)


# ---------------------------------------------------------------- leak score


def test_leak_score_rising_floor() -> None:
    # old floor 300 -> 750 MB of 800 MB over 3 h, very regular
    events = [full(h * 60, 300 + 150 * h) for h in range(4)]
    summary = build_comprehensive_summary(events, TH, gc_type="Parallel GC")
    leak = summary.leak_severity
    assert leak.assessed
    assert any(i.startswith("Old-gen floor rising") for i in leak.indicators)
    assert any(i.startswith("Latest floor at") for i in leak.indicators)
    assert leak.score >= 55
    assert leak.severity_level in ("Medium", "High", "Critical")


def test_leak_not_assessed_without_floors() -> None:
    summary = build_comprehensive_summary([ev(0), ev(1)], TH)
    assert not summary.leak_severity.assessed
    assert summary.leak_severity.indicators[0].startswith("Not assessed")


def test_leak_flat_floor_scores_nothing_for_trend() -> None:
    events = [full(h * 60, 100) for h in range(4)]
    leak = build_comprehensive_summary(events, TH).leak_severity
    assert leak.assessed
    assert not any("rising" in i for i in leak.indicators)


def test_leak_short_floor_window_reports_reason() -> None:
    events = [full(0, 100), full(1, 200)]
    leak = build_comprehensive_summary(events, TH).leak_severity
    assert any(i.startswith("Floor trend not assessed") for i in leak.indicators)


def test_leak_levels_and_headroom() -> None:
    # 2 floors (not assessed) but latest floor 99% of capacity and no headroom
    events = [
        full(0, 790, heap_after_kb=990 * MB, heap_total_kb=1000 * MB),
        full(1, 795, heap_after_kb=999 * MB, heap_total_kb=1000 * MB),
    ]
    leak = build_comprehensive_summary(events, TH).leak_severity
    assert any("headroom" in i for i in leak.indicators)
    assert leak.score == 30.0
    assert leak.severity_level == "Low"


def test_reclamation_declining() -> None:
    reclaimed = [400, 380, 100, 90]
    events = [
        ev(
            i * 60,
            "Full",
            1.0,
            old_before_kb=500 * MB,
            old_after_kb=(500 - r) * MB,
            old_total_kb=800 * MB,
        )
        for i, r in enumerate(reclaimed)
    ]
    summary = build_comprehensive_summary(events, TH)
    assert summary.reclamation_declining
    assert any("reclaims less" in w for w in summary.warnings)


# ---------------------------------------------------------------- allocation (P1.8)


def test_allocation_rate_between_gcs_young_basis() -> None:
    # allocated between GCs = young_before[n] - young_after[n-1] = 100 MB per 10 s
    events = [
        ev(0, young_before_kb=150 * MB, young_after_kb=20 * MB),
        ev(10 / 60, young_before_kb=120 * MB, young_after_kb=20 * MB),
        ev(20 / 60, young_before_kb=120 * MB, young_after_kb=20 * MB),
    ]
    rate, basis = allocation_rate(events)
    assert basis == "young generation"
    assert rate == approx(200 / 20)


def test_allocation_rate_heap_basis_and_degenerate_cases() -> None:
    events = [ev(0, heap_after_kb=100 * MB), ev(1, heap_before_kb=160 * MB)]
    rate, basis = allocation_rate(events)
    assert basis == "whole heap"
    assert rate == approx(60 / 60)
    assert allocation_rate([ev(0)]) == (None, None)
    assert allocation_rate([ev(0), ev(0)]) == (None, None)


# ---------------------------------------------------------------- collectors


def test_cms_metrics() -> None:
    events = [
        ev(0, "Initial Mark", 0.02),
        ev(1, "Remark", 0.04),
        ev(2, "Full", 3.0, concurrent_mode_failure=True),
        ev(3, "Full", 2.0, promotion_failed=True),
    ]
    cms = calculate_cms_metrics(events, None)
    assert (cms.concurrent_cycles, cms.concurrent_mode_failures, cms.promotion_failures) == (
        1,
        1,
        1,
    )
    assert cms.cms_cycle_frequency_per_hour is None
    summary = build_comprehensive_summary(events, TH, gc_type="CMS GC")
    assert any("concurrent mode failure" in w for w in summary.warnings)
    assert any("promotion failure" in w for w in summary.warnings)


def test_g1_metrics_and_warnings() -> None:
    events = [ev(0, humongous_detected=True), ev(1, evacuation_failed=True), ev(2, "Remark")]
    summary = build_comprehensive_summary(events, TH, gc_type="G1 GC")
    g1 = summary.g1_metrics
    assert g1 is not None
    assert (g1.humongous_allocation_count, g1.evacuation_failure_count) == (1, 1)
    assert g1.concurrent_marking_cycles == 1
    assert any("evacuation failure" in w for w in summary.warnings)


def test_overhead_pause_and_heap_warnings() -> None:
    events = [
        ev(0, pause=12.0, heap_after_kb=990 * MB),
        ev(1, pause=12.0, heap_after_kb=990 * MB),
    ]
    summary = build_comprehensive_summary(events, TH)
    joined = " | ".join(summary.warnings)
    assert "CRITICAL: GC overhead" in joined
    assert "CRITICAL: P99 pause" in joined
    assert "CRITICAL: Heap after GC peaked at 99.0% of committed heap" in joined
    assert any("Max heap (-Xmx) not found" in n for n in summary.data_notes)


def test_moderate_warnings() -> None:
    events = [ev(0, pause=6.0, heap_after_kb=850 * MB), ev(1, pause=6.0)]
    th = DiagnosticThresholds(
        gc_overhead_warning_percentage=5.0, gc_overhead_critical_percentage=500.0
    )
    joined = " | ".join(build_comprehensive_summary(events, th).warnings)
    assert "WARNING: GC overhead" in joined
    assert "WARNING: P99 pause" in joined
    assert "WARNING: Heap after GC peaked at 85.0%" in joined


def test_metaspace_analysis_growth() -> None:
    events = [
        ev(0, metaspace_before_kb=10, metaspace_after_kb=100 * MB, metaspace_total_kb=105 * MB),
        ev(1, metaspace_before_kb=10, metaspace_after_kb=170 * MB, metaspace_total_kb=180 * MB),
    ]
    meta = build_comprehensive_summary(events, TH).metaspace_analysis
    assert meta is not None
    assert meta.metaspace_growth_kb == 70 * MB
    assert meta.metaspace_growing
    assert any("peaked" in w for w in meta.metaspace_warnings)


def test_period_stats_three_buckets() -> None:
    events = [
        ev(m, old_after_kb=m * MB, old_total_kb=100 * MB, old_used_percentage=float(m))
        for m in (0, 30, 60, 90)
    ]
    periods = build_comprehensive_summary(events, TH).period_stats
    assert set(periods) == {"early", "middle", "late"}
    assert periods["early"].average_old_gen_percentage == 0.0
