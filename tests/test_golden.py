"""Golden fixtures: every number compared with a hand-computed expected.json."""

from __future__ import annotations

import json
from typing import Any

import pytest

from gc_analyze.analysis import classify_full_gc_cause
from gc_analyze.pipeline import run_analysis
from gc_analyze.report import format_time

from .support import FIXTURES, approx

GOLDEN = sorted(p.name.replace(".expected.json", ".log") for p in FIXTURES.glob("*.expected.json"))


def test_every_fixture_has_expected_values() -> None:
    logs = {p.name for p in FIXTURES.glob("*.log")}
    assert logs == set(GOLDEN)


@pytest.mark.parametrize("name", GOLDEN)
def test_golden(name: str) -> None:
    expected: dict[str, Any] = json.loads(
        (FIXTURES / name.replace(".log", ".expected.json")).read_text()
    )
    result = run_analysis([FIXTURES / name])
    summary = result.summary
    events = result.events

    assert result.gc_type == expected["gc_type"]
    assert len(result.segments) == expected["segments"]
    if "segment_events" in expected:
        assert [s.events for s in result.segments] == expected["segment_events"]
    assert summary.counts_by_kind == expected["counts_by_kind"]
    for kind, causes in expected.get("causes_by_kind", {}).items():
        assert summary.causes_by_kind[kind] == causes

    categories = {"heap": 0, "explicit": 0, "metadata": 0}
    for event in events:
        if event.gc_kind == "Full":
            categories[classify_full_gc_cause(event.cause)] += 1
    assert categories == expected["full_gc_categories"]
    assert summary.heap_full_gc_count == expected["full_gc_categories"]["heap"]

    pauses = [e.pause_time_seconds for e in events]
    assert len(pauses) == expected["pauses"]["count"]
    assert sum(pauses) == approx(expected["pauses"]["sum"], abs=1e-9)
    assert min(pauses) == approx(expected["pauses"]["min"])
    assert max(pauses) == approx(expected["pauses"]["max"])

    first, last = events[0], events[-1]
    assert format_time(first.timestamp, first.wall_clock, first.uptime_seconds) == expected["first"]
    assert format_time(last.timestamp, last.wall_clock, last.uptime_seconds) == expected["last"]

    coverage = result.coverage
    assert coverage.candidate_lines == expected["coverage"]["candidates"]
    assert coverage.parsed_candidate_lines == expected["coverage"]["parsed"]
    assert coverage.continuation_lines == expected["coverage"]["continuation"]

    flags = expected["flags"]
    assert sum(e.evacuation_failed for e in events) == flags["evacuation_failed"]
    assert sum(e.to_space_exhausted for e in events) == flags["to_space_exhausted"]
    assert sum(e.humongous_detected for e in events) == flags["humongous"]
    assert sum(e.concurrent_mode_failure for e in events) == flags["concurrent_mode_failure"]
    assert sum(e.promotion_failed for e in events) == flags["promotion_failed"]

    trend = summary.floor_trend
    floors = expected["floors"]
    assert [f.value_kb / 1024 for f in trend.floors] == approx(floors["mb"])
    if floors["mb"]:
        assert trend.metric == floors["metric"]
    assert trend.assessed is floors["assessed"]
    if floors["slope_mb_per_hour"] is None:
        assert trend.slope_mb_per_hour is None
    else:
        assert trend.slope_mb_per_hour == approx(floors["slope_mb_per_hour"], abs=1e-4)

    if expected["max_heap_kb"] is None:
        assert not summary.heap.max_heap_known
    else:
        assert summary.heap.max_heap_known
        assert summary.heap.max_heap_kb == expected["max_heap_kb"]
