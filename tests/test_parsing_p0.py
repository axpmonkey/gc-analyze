"""Regression tests for the P0 parsing gaps (see work-tools/10-gc-analyze-improvements.md)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from typer.testing import CliRunner

from gc_analyze.cli import app
from gc_analyze.coverage import (
    build_unparsed_warning,
    compute_candidate_coverage,
    is_gc_candidate_line,
)
from gc_analyze.events import UPTIME_EPOCH, normalize_event
from gc_analyze.models import CandidateCoverage, GCEvent
from gc_analyze.parsers import (
    CMSGCParser,
    G1LegacyGCParser,
    ParallelGCParser,
    UnifiedGCParser,
    detect_gc_type_and_create_parser,
)
from gc_analyze.report import build_parsing_coverage_rows, build_time_window_rows

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def load(name: str) -> list[str]:
    with (FIXTURES / name).open() as handle:
        return handle.readlines()


def parse_fixture(name: str) -> tuple[str, list[GCEvent], CandidateCoverage]:
    lines = load(name)
    parser = detect_gc_type_and_create_parser(lines)
    raw_events = parser.parse(lines)
    events = [e for e in (normalize_event(r) for r in raw_events) if e is not None]
    return parser.gc_type_name, events, compute_candidate_coverage(lines, raw_events)


def kinds(events: list[GCEvent]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for event in events:
        counts[event.gc_kind] = counts.get(event.gc_kind, 0) + 1
    return counts


# ---------------------------------------------------------------- P0.1


@pytest.mark.parametrize(
    "line",
    [
        "2016-08-23T02:23:07.219-0200: 64.322: [GC (Allocation Failure) 64.322: [ParNew: ...",
        "10.000: [Full GC (System.gc()) [PSYoungGen: 10000K->0K(76288K)] ...",
        "2020-01-01T10:00:00.000+0000: 10.000: [GC pause (G1 Evacuation Pause) (young), 0.02 secs]",
        "2020-01-01T10:03:00.000+0000: 190.000: [GC remark ..., 0.0500000 secs]",
        "[10.000s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 100M->20M(1G) 20ms",
        "[1.0s][info][gc] GC(9) Pause Remark 50M->50M(256M) 1.234ms",
    ],
)
def test_candidate_lines_detected(line: str) -> None:
    assert is_gc_candidate_line(line)


@pytest.mark.parametrize(
    "line",
    [
        # unified gc,start opener: the pause record is the later line ending in "ms"
        "[10.000s][info][gc,start] GC(0) Pause Young (Normal) (G1 Evacuation Pause)",
        # unified heap detail line for the same GC id
        "[10.000s][info][gc,heap] GC(0) ParNew: 1000K->100K(2000K)",
        # legacy G1 concurrent phase
        "2020-01-01T10:00:00.000+0000: 10.5: [GC concurrent-mark-end, 0.0123 secs]",
        "   [Eden: 100.0M(100.0M)->0.0B(100.0M) Survivors: 10.0M->10.0M Heap: 500.0M(1024.0M)]",
        "CommandLine flags: -XX:+UseParNewGC -XX:+UseConcMarkSweepGC",
    ],
)
def test_non_candidate_lines_ignored(line: str) -> None:
    assert not is_gc_candidate_line(line)


def test_coverage_counts_unparsed_candidates_and_samples() -> None:
    lines = ["a: [GC (x) parsed\n", "b: [GC (x) not parsed\n", "plain text\n"]
    coverage = compute_candidate_coverage(lines, [{"line_index": 0}])
    assert coverage.candidate_lines == 2
    assert coverage.parsed_candidate_lines == 1
    assert coverage.unparsed_candidate_lines == 1
    assert coverage.unparsed_percentage == 50.0
    assert coverage.unparsed_samples == ["L2: b: [GC (x) not parsed"]


def test_coverage_samples_are_capped_and_truncated() -> None:
    lines = [f"[GC {'x' * 300}\n"] * 8
    coverage = compute_candidate_coverage(lines, [])
    assert len(coverage.unparsed_samples) == 5
    assert all(len(sample) <= 160 + len("L1: ") for sample in coverage.unparsed_samples)
    assert coverage.unparsed_samples[0].endswith("...")


def test_unparsed_warning_threshold() -> None:
    assert build_unparsed_warning(None) is None
    assert (
        build_unparsed_warning(CandidateCoverage(candidate_lines=0, parsed_candidate_lines=0))
        is None
    )
    # exactly 1% is not over the threshold
    assert (
        build_unparsed_warning(CandidateCoverage(candidate_lines=100, parsed_candidate_lines=99))
        is None
    )
    warning = build_unparsed_warning(CandidateCoverage(candidate_lines=4, parsed_candidate_lines=1))
    assert warning is not None
    assert "3 of 4" in warning


def test_coverage_rows_include_candidates_and_samples() -> None:
    coverage = CandidateCoverage(
        candidate_lines=4, parsed_candidate_lines=1, unparsed_samples=["L1: [GC x"]
    )
    rows = dict(build_parsing_coverage_rows(coverage, usable_events=1, events_without_heap=0))
    assert rows["GC event lines found"] == "4"
    assert rows["GC event lines parsed"] == "1"
    assert rows["GC event lines NOT parsed"] == "3 (75.0%)"
    assert rows["Unparsed sample"] == "L1: [GC x"


# ---------------------------------------------------------------- P0.2


def test_cms_inner_uptime_prefix() -> None:
    gc_type, events, coverage = parse_fixture("cms.log")
    assert gc_type == "CMS GC"
    assert kinds(events) == {"Young": 2, "Initial Mark": 1, "Full": 1}
    young = [e for e in events if e.gc_kind == "Young"]
    # outer total, not the ParNew-internal 0.1020465
    assert [e.pause_time_seconds for e in young] == [0.1021309, 0.1021309]
    (full,) = [e for e in events if e.gc_kind == "Full"]
    assert full.pause_time_seconds == 3.2
    assert (full.old_before_kb, full.old_after_kb) == (11000000, 9000000)
    assert full.metaspace_after_kb == 50000
    (initial_mark,) = [e for e in events if e.gc_kind == "Initial Mark"]
    assert initial_mark.pause_time_seconds == 0.0001997
    assert coverage.unparsed_candidate_lines == 0


def test_cms_inner_datestamp_and_uptime_prefix() -> None:
    lines = [
        "2016-08-23T02:23:07.219-0200: 64.322: [GC (Allocation Failure) "
        "2016-08-23T02:23:07.219-0200: 64.322: [ParNew: 613404K->68068K(613440K), "
        "0.1020465 secs] 10885349K->10880154K(12514816K), 0.1021309 secs]\n",
        "2016-08-23T02:26:07.219-0200: 244.322: [Full GC (Allocation Failure) "
        "2016-08-23T02:26:07.219-0200: 244.322: [CMS: 11000000K->9000000K(11901376K), "
        "3.1 secs] 11500000K->9100000K(12514816K), "
        "[Metaspace: 50000K->50000K(1093632K)], 3.2 secs]\n",
        # layout without the inner stamp keeps working
        "2016-08-23T02:27:07.219-0200: 304.322: [GC (Allocation Failure) [ParNew: "
        "613404K->68068K(613440K), 0.1 secs] 10885349K->10880154K(12514816K), 0.2 secs]\n",
    ]
    raw = CMSGCParser().parse(lines)
    assert [(r["gc_kind"], r["pause"]) for r in raw] == [
        ("Young", 0.1021309),
        ("Full", 3.2),
        ("Young", 0.2),
    ]
    assert raw[1]["old_after"] == 9000000


# ---------------------------------------------------------------- P0.3 - P0.5


def test_g1_legacy_full_gc_to_space_and_remark_total() -> None:
    gc_type, events, coverage = parse_fixture("g1legacy.log")
    assert gc_type == "G1 GC"
    assert kinds(events) == {"Young": 3, "Full": 1, "Remark": 1}
    assert coverage.unparsed_candidate_lines == 0

    by_uptime = {e.uptime_seconds: e for e in events}
    # P0.4: the to-space exhausted pause is parsed and carries the flag itself
    exhausted = by_uptime[70.0]
    assert exhausted.gc_kind == "Young"
    assert exhausted.pause_time_seconds == 0.9
    assert exhausted.to_space_exhausted and exhausted.evacuation_failed
    assert [e.uptime_seconds for e in events if e.evacuation_failed] == [70.0]

    # P0.3: Full GC with heap from the header, old gen from the detail line
    full = by_uptime[130.0]
    assert full.gc_kind == "Full"
    assert full.pause_time_seconds == 4.5
    assert (full.heap_before_kb, full.heap_after_kb) == (1020 * 1024, 600 * 1024)
    assert full.old_after_kb == 600 * 1024

    # P0.5: remark total, not the first sub-phase
    assert by_uptime[190.0].pause_time_seconds == 0.05


@pytest.mark.parametrize(
    ("tags", "kind", "to_space"),
    [
        ("(G1 Evacuation Pause) (young)", "Young", False),
        ("(G1 Evacuation Pause) (mixed)", "Mixed", False),
        ("(G1 Humongous Allocation) (young) (initial-mark)", "Young", False),
        ("(G1 Evacuation Pause) (mixed) (to-space overflow)", "Mixed", True),
    ],
)
def test_g1_legacy_pause_tags(tags: str, kind: str, to_space: bool) -> None:
    lines = [
        f"2020-01-01T10:00:00.000+0000: 10.000: [GC pause {tags}, 0.0200000 secs]\n",
        "   [Eden: 1.0M(1.0M)->0.0B(1.0M) Survivors: 0.0B->0.0B Heap: 5.0M(10.0M)->4.0M(10.0M)]\n",
    ]
    (raw,) = G1LegacyGCParser().parse(lines)
    assert raw["gc_kind"] == kind
    assert raw["to_space_exhausted"] is to_space
    assert raw["humongous_detected"] is ("Humongous" in tags)


def test_g1_legacy_full_gc_without_detail_line_and_nested_cause() -> None:
    lines = [
        "2020-01-01T10:02:00.000+0000: 130.000: [Full GC (System.gc())  1020M->600M(1024M), "
        "4.5000000 secs]\n",
        "2020-01-01T10:04:00.000+0000: 250.000: [GC pause (G1 Evacuation Pause) (young), "
        "0.0200000 secs]\n",
        "   [Eden: 1.0M(1.0M)->0.0B(1.0M) Survivors: 0.0B->0.0B Heap: 5.0M(10.0M)->4.0M(10.0M)]\n",
    ]
    raw = G1LegacyGCParser().parse(lines)
    assert [(r["gc_kind"], r["pause"]) for r in raw] == [("Full", 4.5), ("Young", 0.02)]


# ---------------------------------------------------------------- P0.6


@pytest.mark.parametrize("name", ["g1unified_uptime.log", "parallel_uptime_only.log"])
def test_uptime_only_logs(name: str) -> None:
    _, events, coverage = parse_fixture(name)
    assert kinds(events) == {"Young": 2, "Full": 1}
    assert coverage.unparsed_candidate_lines == 0
    assert not any(e.wall_clock for e in events)
    assert [e.uptime_seconds for e in events] == [10.0, 70.0, 130.0]
    # intervals stay correct even without wall-clock time
    assert (events[-1].timestamp - events[0].timestamp) == timedelta(seconds=120)


def test_uptime_only_anchored_with_jvm_start() -> None:
    lines = load("g1unified_uptime.log")
    raw = detect_gc_type_and_create_parser(lines).parse(lines)
    start = datetime(2026, 11, 10, 14, 0, tzinfo=timezone(timedelta(hours=-5)))
    events = [e for e in (normalize_event(r, start) for r in raw) if e is not None]
    assert events[0].wall_clock
    assert events[0].timestamp == start + timedelta(seconds=10)


def test_log_datestamp_wins_over_jvm_start() -> None:
    lines = load("g1legacy.log")
    raw = detect_gc_type_and_create_parser(lines).parse(lines)
    event = normalize_event(raw[0], datetime(2000, 1, 1, tzinfo=UTC))
    assert event is not None
    assert event.timestamp == datetime(2020, 1, 1, 10, 0, tzinfo=UTC)


def test_date_only_legacy_line_is_parsed_without_uptime() -> None:
    # Without -XX:+PrintGCTimeStamps there is no uptime; "07.219" inside the datestamp must
    # not be taken as one.
    line = (
        "2016-08-23T02:23:07.219-0200: [GC (Allocation Failure) [PSYoungGen: "
        "65536K->10000K(76288K)] 65536K->10008K(251392K), 0.0100000 secs]\n"
    )
    (raw,) = ParallelGCParser().parse([line])
    assert raw["uptime"] is None
    assert raw["timestamp"] == "2016-08-23T02:23:07.219-0200"
    assert raw["pause"] == 0.01


def test_unified_padded_level_is_parsed() -> None:
    line = "[10.000s][info ][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 1M->1M(4M) 2ms\n"
    (raw,) = UnifiedGCParser().parse([line])
    assert raw["pause"] == 0.002


def test_time_window_rows_without_wall_clock() -> None:
    rows = dict(build_time_window_rows(UPTIME_EPOCH, UPTIME_EPOCH, 10.0, 130.0, wall_clock=False))
    assert rows["First event timestamp"].startswith("n/a")
    assert rows["Last event uptime"] == "130.000s"


def test_cli_jvm_start_validation() -> None:
    log = str(FIXTURES / "parallel_uptime_only.log")
    bad = runner.invoke(app, ["analyze", log, "--jvm-start", "yesterday"])
    assert bad.exit_code == 2
    assert "ISO 8601" in bad.output
    naive = runner.invoke(app, ["analyze", log, "--jvm-start", "2026-11-10T14:00:00"])
    assert naive.exit_code == 2
    ok = runner.invoke(app, ["analyze", log, "--jvm-start", "2026-11-10T14:00:00-05:00"])
    assert "2026-11-10T14:00:10.000-05:00" in ok.output


# ---------------------------------------------------------------- P0.7


def test_parallel_unified_routed_to_unified_parser() -> None:
    gc_type, events, coverage = parse_fixture("parallel_unified.log")
    assert gc_type == "Parallel GC"
    assert isinstance(
        detect_gc_type_and_create_parser(load("parallel_unified.log")), UnifiedGCParser
    )
    assert kinds(events) == {"Young": 2}
    assert [e.pause_time_seconds for e in events] == [0.012, 0.014]
    # PSYoungGen heap line logged before the pause line is attached by GC id
    assert (events[0].young_before_kb, events[0].young_after_kb) == (65536, 10000)
    assert coverage.unparsed_candidate_lines == 0


def test_unified_generation_lines_before_and_after_pause() -> None:
    lines = [
        "[1.000s][info][gc] Using Parallel\n",
        # JDK 17 layout, logged before the pause line
        "[2.000s][info][gc,heap] GC(0) PSYoungGen: 65536K(76288K)->10000K(76288K) Eden: ...\n",
        "[2.000s][info][gc,heap] GC(0) ParOldGen: 1000K(175104K)->2000K(175104K)\n",
        "[2.000s][info][gc] GC(0) Pause Young (Allocation Failure) 64M->20M(251M) 12.000ms\n",
        # JDK 11 layout, logged after the pause line
        "[3.000s][info][gc] GC(1) Pause Full (Ergonomics) 74M->30M(251M) 50.000ms\n",
        "[3.000s][info][gc,heap] GC(1) ParOldGen: 2000K->1500K(175104K)\n",
    ]
    parser = detect_gc_type_and_create_parser(lines)
    young, full = parser.parse(lines)
    assert (young["young_before"], young["young_after"], young["young_total"]) == (
        65536,
        10000,
        76288,
    )
    assert (young["old_before"], young["old_after"], young["old_total"]) == (1000, 2000, 175104)
    assert full["gc_kind"] == "Full"
    assert (full["old_before"], full["old_after"]) == (2000, 1500)


@pytest.mark.parametrize(
    ("header", "body", "expected"),
    [
        ("Using G1", "", "G1 GC"),
        ("Using Parallel", "", "Parallel GC"),
        ("Using Serial", "", "Serial GC"),
        ("Using Concurrent Mark Sweep", "", "CMS GC"),
        # rotated file without the header: infer from generation names
        ("Heap region size: 1M", "GC(0) PSYoungGen: 1K->1K(2K)", "Parallel GC"),
        ("Heap region size: 1M", "GC(0) DefNew: 1K->1K(2K)", "Serial GC"),
        ("Heap region size: 1M", "GC(0) ParNew: 1K->1K(2K)", "CMS GC"),
        ("Heap region size: 1M", "GC(0) Eden regions: 1->0(2)", "G1 GC"),
    ],
)
def test_unified_collector_detection(header: str, body: str, expected: str) -> None:
    lines = [f"[0.010s][info][gc] {header}\n", f"[1.000s][info][gc,heap] {body}\n"]
    assert detect_gc_type_and_create_parser(lines).gc_type_name == expected


@pytest.mark.parametrize(
    ("line", "name"),
    [
        ("[0.010s][info][gc] Using The Z Garbage Collector", "ZGC"),
        ("[0.010s][info][gc] Using Shenandoah", "Shenandoah"),
        ("[0.010s][info][gc] Using Epsilon", "Epsilon"),
        ("[1.0s][info][gc] GC(0) Garbage Collection (Warmup) 10M(5%)->8M(4%)", "ZGC"),
        ("[1.0s][info][gc] GC(0) Pause Init Mark 0.2ms", "Shenandoah"),
    ],
)
def test_unsupported_unified_collectors_named(line: str, name: str) -> None:
    with pytest.raises(ValueError, match=f"^{name} logs are not supported"):
        detect_gc_type_and_create_parser([line + "\n"])


def test_legacy_detection_unchanged() -> None:
    assert detect_gc_type_and_create_parser(load("cms.log")).gc_type_name == "CMS GC"
    assert detect_gc_type_and_create_parser(load("g1legacy.log")).gc_type_name == "G1 GC"
    parallel = detect_gc_type_and_create_parser(load("parallel_uptime_only.log"))
    assert isinstance(parallel, ParallelGCParser)
    with pytest.raises(ValueError, match="unrecognized"):
        detect_gc_type_and_create_parser(["hello\n"])


def test_cli_reports_unsupported_collector(tmp_path: Path) -> None:
    log = tmp_path / "zgc.log"
    log.write_text("[0.010s][info][gc] Using The Z Garbage Collector\n")
    result = runner.invoke(app, ["analyze", str(log)])
    assert result.exit_code == 1
    assert "ZGC logs are not supported" in result.output


def test_cli_no_usable_events_reports_coverage(tmp_path: Path) -> None:
    log = tmp_path / "bad.log"
    log.write_text("1.0: [GC (Allocation Failure) [PSYoungGen: garbled\n")
    result = runner.invoke(app, ["analyze", str(log)])
    assert result.exit_code == 1
    assert "1 GC event lines found, 0 parsed." in result.output
    assert "Unparsed sample L1:" in result.output


def test_cli_markdown_includes_incomplete_parse_warning(tmp_path: Path) -> None:
    log = tmp_path / "partial.log"
    lines = [*load("g1legacy.log"), "2020-01-01T10:05:00.000+0000: 310.000: [GC pause garbled\n"]
    log.write_text("".join(lines))
    report = tmp_path / "report.md"
    result = runner.invoke(app, ["analyze", str(log), "--output", str(report)])
    assert "Incomplete Parse" in result.output
    markdown = report.read_text()
    assert "> **WARNING: 1 of 6 GC event lines (16.7%)" in markdown
    assert "- **Unparsed sample:** L10: " in markdown
