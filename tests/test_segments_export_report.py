"""JVM restarts and multiple files (P1.9), event export (P2.1), report sections (P2.3/P2.4)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from rich.console import Console

from gc_analyze.export import ExportError, event_level, event_record, export_events
from gc_analyze.markdown import BRIEF_MAX_BYTES, render_brief_markdown, render_markdown
from gc_analyze.pipeline import NoEventsError, parse_time_option, run_analysis
from gc_analyze.report import (
    GC_ANALYZE_THEME,
    ReportContext,
    build_sections,
    describe_pause_clustering,
    determine_overall_status,
    render_rich,
)
from gc_analyze.segments import filter_window, select_segment

from .support import FIXTURES

PARALLEL_LINE = (
    "{date}: {up:.3f}: [GC (Allocation Failure) [PSYoungGen: 65536K->8192K(76288K)] "
    "65536K->8200K(251392K), 0.0100000 secs]\n"
)


def write_log(path: Path, start: datetime, uptimes: list[float], header: bool = True) -> Path:
    lines = ["CommandLine flags: -XX:+UseParallelGC \n"] if header else []
    for up in uptimes:
        date = (start + timedelta(seconds=up)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
        lines.append(PARALLEL_LINE.format(date=date, up=up))
    path.write_text("".join(lines))
    return path


# ---------------------------------------------------------------- segments


def test_restart_detected_and_latest_segment_analyzed() -> None:
    result = run_analysis([FIXTURES / "restart_in_middle.log"])
    assert [s.events for s in result.segments] == [2, 3]
    assert result.segment_label == "segment 2 of 2"
    first = run_analysis([FIXTURES / "restart_in_middle.log"], segment="1")
    assert first.summary.total_event_count == 2
    everything = run_analysis([FIXTURES / "restart_in_middle.log"], segment="all")
    assert everything.summary.total_event_count == 5
    assert everything.segment_label == "all segments"


@pytest.mark.parametrize(("choice", "message"), [("x", "must be"), ("9", "segments 1-2")])
def test_bad_segment_choice(choice: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        run_analysis([FIXTURES / "restart_in_middle.log"], segment=choice)


def test_header_without_uptime_reset_starts_segment(tmp_path: Path) -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    log = write_log(tmp_path / "a.log", start, [10, 20])
    text = log.read_text() + "CommandLine flags: -XX:+UseParallelGC \n"
    date = (start + timedelta(seconds=40)).strftime("%Y-%m-%dT%H:%M:%S.000+0000")
    log.write_text(text + PARALLEL_LINE.format(date=date, up=40.0))
    assert [s.events for s in run_analysis([log]).segments] == [2, 1]


def test_rotated_files_are_ordered_and_continue(tmp_path: Path) -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    second = write_log(tmp_path / "gc.log.1", start, [3000, 4000], header=False)
    first = write_log(tmp_path / "gc.log.0", start, [10, 2000])
    result = run_analysis([second, first])  # given out of order
    assert [f.path.name for f in result.files] == ["gc.log.0", "gc.log.1"]
    assert len(result.segments) == 1
    assert result.summary.total_event_count == 4
    assert len(result.file_coverages) == 2


def test_files_from_two_jvm_runs_are_separate_segments(tmp_path: Path) -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    a = write_log(tmp_path / "a.log", start, [10, 20])
    b = write_log(tmp_path / "b.log", start + timedelta(hours=1), [5, 6])
    result = run_analysis([a, b])
    assert [s.events for s in result.segments] == [2, 2]


def test_uptime_only_files_ordered_by_uptime(tmp_path: Path) -> None:
    a = tmp_path / "a.log"
    b = tmp_path / "b.log"
    a.write_text(
        "CommandLine flags: -XX:+UseParallelGC \n"
        + PARALLEL_LINE.split(": ", 1)[1].format(up=500.0)
    )
    b.write_text(
        "CommandLine flags: -XX:+UseParallelGC \n"
        + PARALLEL_LINE.split(": ", 1)[1].format(up=100.0)
    )
    result = run_analysis([a, b])
    assert [f.path.name for f in result.files] == ["b.log", "a.log"]


def test_mixed_collectors_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="different collectors"):
        run_analysis([FIXTURES / "cms.log", FIXTURES / "g1legacy.log"])


def test_no_events_error_carries_coverage(tmp_path: Path) -> None:
    log = tmp_path / "x.log"
    log.write_text("1.0: [GC (Allocation Failure) [PSYoungGen: broken\n")
    with pytest.raises(NoEventsError) as info:
        run_analysis([log])
    assert info.value.coverage.candidate_lines == 1


def test_detection_error_names_file(tmp_path: Path) -> None:
    log = tmp_path / "x.log"
    log.write_text("hello\n")
    with pytest.raises(ValueError, match=r"x\.log: Unsupported"):
        run_analysis([log])


def test_select_segment_single_and_filter_window() -> None:
    result = run_analysis([FIXTURES / "cms.log"])
    events, label = select_segment(result.all_events, result.segments, "latest")
    assert label == "single JVM run"
    t = events[1].timestamp
    assert len(filter_window(events, t, None)) == 3
    assert len(filter_window(events, None, t)) == 2


# ---------------------------------------------------------------- time window (P2.2)


def test_parse_time_option() -> None:
    tz = UTC
    assert parse_time_option(None, "--start", tz) is None
    assert parse_time_option("2024-01-01T00:00:00", "--start", tz) == datetime(
        2024, 1, 1, tzinfo=UTC
    )
    with pytest.raises(ValueError, match="not an ISO"):
        parse_time_option("noon", "--start", tz)
    with pytest.raises(ValueError, match="UTC offset"):
        parse_time_option("2024-01-01T00:00:00", "--jvm-start", None)


def test_window_with_previous_day_comparison(tmp_path: Path) -> None:
    start = datetime(2024, 1, 1, tzinfo=UTC)
    day = 86400.0
    log = write_log(tmp_path / "gc.log", start, [100, 200, 300, day + 100, day + 150])
    result = run_analysis([log], start="2024-01-02T00:01:00", end="2024-01-02T00:03:00")
    assert result.summary.total_event_count == 2
    assert result.comparison is not None
    # previous day 00:01-00:03 holds only the pause at 00:01:40 (the next is at 00:03:20)
    assert result.comparison.total_event_count == 1
    assert result.window_label is not None and result.window_label.startswith("window 2024-01-02")


def test_window_errors(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="No GC pauses"):
        run_analysis([FIXTURES / "cms.log"], start="2030-01-01T00:00:00+00:00")
    with pytest.raises(ValueError, match="need wall-clock"):
        run_analysis([FIXTURES / "serial_legacy.log"], start="2030-01-01T00:00:00+00:00")


# ---------------------------------------------------------------- export (P2.1)


def test_export_events_shared_format(tmp_path: Path) -> None:
    result = run_analysis([FIXTURES / "cms_failures.log"])
    path = tmp_path / "gc.events.jsonl"
    count = export_events(result.events, path, host="host-03", max_heap_kb=2097152)
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert count == len(records) == 6
    first = records[0]
    assert first["ts"] == "2021-05-01T10:00:10.000Z"
    assert first["ts_raw"] == "2021-05-01T10:00:10.000+0000"
    assert first["tz_source"] == "in-line"
    assert (first["source"], first["host"], first["line"]) == ("gc", "host-03", 4)
    assert first["duration_ms"] == 31.0
    assert first["level"] == "INFO"
    assert first["attrs"]["kind"] == "Young"
    assert first["attrs"]["max_heap_kb"] == 2097152
    assert (
        first["signature"].startswith("gc:INFO:")
        and len(first["signature"]) == len("gc:INFO:") + 12
    )
    cmf = next(r for r in records if r["attrs"].get("concurrent_mode_failure"))
    assert cmf["level"] == "WARN"
    explicit = next(r for r in records if r["attrs"]["cause"] == "System.gc()")
    assert explicit["level"] == "INFO"


def test_export_needs_wall_clock() -> None:
    result = run_analysis([FIXTURES / "serial_legacy.log"])
    with pytest.raises(ExportError, match="--jvm-start"):
        event_record(result.events[0], host=None, max_heap_kb=None)


def test_export_jvm_start_tz_source() -> None:
    anchor = datetime(2026, 1, 1, 9, 0, tzinfo=UTC)
    result = run_analysis([FIXTURES / "serial_legacy.log"], jvm_start=anchor)
    record = event_record(result.events[0], host=None, max_heap_kb=None)
    assert record["tz_source"] == "cli:2026-01-01T09:00:00+00:00"
    assert record["ts"] == "2026-01-01T09:00:01.500Z"
    assert record["ts_raw"] == "uptime 1.500s"


def test_event_level_heap_full_gc_is_warn() -> None:
    result = run_analysis([FIXTURES / "parallel_legacy_datestamps.log"])
    levels = {(e.cause, event_level(e)) for e in result.events if e.gc_kind == "Full"}
    assert levels == {
        ("Metadata GC Threshold", "INFO"),
        ("System.gc()", "INFO"),
        ("Ergonomics", "WARN"),
    }


# ---------------------------------------------------------------- report & markdown


def context(name: str, **kwargs: str) -> ReportContext:
    result = run_analysis([FIXTURES / name], **kwargs)  # type: ignore[arg-type]
    return ReportContext(
        summary=result.summary,
        gc_type=result.gc_type,
        events=result.events,
        coverage=result.coverage,
        file_coverages=result.file_coverages,
        segments=result.segments,
        segment_label=result.segment_label,
        window_label=result.window_label,
        comparison=result.comparison,
        comparison_label=result.comparison_label,
    )


@pytest.mark.parametrize("name", sorted(p.name for p in FIXTURES.glob("*.log")))
def test_every_fixture_renders(name: str) -> None:
    sections = build_sections(context(name))
    console = Console(record=True, width=120, theme=GC_ANALYZE_THEME)
    render_rich(sections, console)
    text = console.export_text()
    assert "Incident Summary" in text
    markdown = render_markdown(sections)
    assert markdown.startswith("# GC Analysis Report")
    brief = render_brief_markdown(sections)
    assert len(brief.encode()) <= BRIEF_MAX_BYTES
    assert "Incident Summary" in brief


def test_incident_summary_content() -> None:
    sections = {s.id: s for s in build_sections(context("cms_failures.log"))}
    text = sections["incident"].text
    assert "Worst pauses:" in text
    assert "Full (Allocation Failure; concurrent mode failure)" in text
    assert "Full (Allocation Failure; promotion failed)" in text
    assert "Live set: Old-gen floor 879 MB → 1.05 GB; rising, slope +97.7 MB/h (r²=1.00)" in text
    assert "Full GCs: 3 (2 Allocation Failure, 1 System.gc())." in text
    assert "Data quality: all 6 GC lines parsed." in text


def test_segments_section_only_with_restarts() -> None:
    ids = {s.id for s in build_sections(context("restart_in_middle.log"))}
    assert "segments" in ids
    assert "segments" not in {s.id for s in build_sections(context("cms.log"))}


def test_brief_markdown_large_input_stays_under_budget() -> None:
    sections = build_sections(context("parallel_floor_slope.log"))
    brief = render_brief_markdown(sections)
    assert len(brief.encode()) <= BRIEF_MAX_BYTES
    assert "Key JVM Flags" in brief
    assert "Floors (occupancy after cleaning collections) (12 of 13, evenly spaced)" in brief


def test_brief_truncates_when_needed() -> None:
    sections = build_sections(context("cms.log"))
    notes = next(s for s in sections if s.id == "notes")
    notes.items = ["x" * 400] * 30
    brief = render_brief_markdown(sections)
    assert brief.endswith("_(truncated to 5 KB)_\n")
    assert len(brief.encode()) <= BRIEF_MAX_BYTES + 40


def test_clustering_sentence() -> None:
    events = run_analysis([FIXTURES / "parallel_floor_slope.log"]).events
    assert describe_pause_clustering(events).startswith("The 5 longest pauses are spread")
    assert describe_pause_clustering(events[:1]) == ""


def test_overall_status_levels() -> None:
    summary = run_analysis([FIXTURES / "cms_failures.log"]).summary
    assert determine_overall_status(summary)[1] == "critical"
    summary.warnings = ["CRITICAL: a", "CRITICAL: b", "CRITICAL: c"]
    assert determine_overall_status(summary)[0].startswith("✖ CRITICAL")
    summary.warnings = ["WARNING: a"]
    assert determine_overall_status(summary)[1] == "warning"
    summary.warnings = []
    assert determine_overall_status(summary)[1] == "success"
