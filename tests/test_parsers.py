"""Parser behaviour beyond the golden fixtures: layouts, decorators, detection, noise."""

from __future__ import annotations

import pytest

from gc_analyze.coverage import compute_candidate_coverage
from gc_analyze.parsers import (
    G1LegacyGCParser,
    GenerationalGCParser,
    ParallelGCParser,
    UnifiedGCParser,
    apply_region_counts,
    detect_gc_type_and_create_parser,
    iter_legacy_records,
    paren_contents,
    parse_unified_prefix,
)

from .support import kinds, parse_lines

# ---------------------------------------------------------------- legacy records


def test_paren_contents_handles_nesting() -> None:
    assert paren_contents("(System.gc()) (young) ") == ["System.gc()", "young"]


def test_record_joining_stops_at_next_record() -> None:
    lines = [
        "1.000: [GC (Allocation Failure) [PSYoungGen\n",  # never balanced
        "2.000: [GC (Allocation Failure) [PSYoungGen: 1K->1K(2K)] 1K->1K(4K), 0.01 secs]\n",
    ]
    records = list(iter_legacy_records(lines))
    assert [(start, end) for start, end, _ in records] == [(0, 0), (1, 1)]


def test_record_joining_is_capped() -> None:
    lines = ["1.000: [GC (Allocation Failure) [ParNew\n"] + ["noise\n"] * 100
    ((start, end, _),) = list(iter_legacy_records(lines))
    assert (start, end) == (0, 40)


def test_reference_gc_noise_is_removed() -> None:
    line = (
        "10.000: [GC (Allocation Failure) 10.000: [SoftReference, 0 refs, 0.0000100 secs]"
        "10.000: [WeakReference, 5 refs, 0.0000100 secs]10.000: [FinalReference, 1 refs, "
        "0.0000100 secs]10.000: [PhantomReference, 0 refs, 0 refs, 0.0000100 secs]10.000: "
        "[JNI Weak Reference, 0.0000100 secs][PSYoungGen: 65536K->10000K(76288K)] "
        "65536K->10008K(251392K), 0.0100000 secs] [Times: user=0.01 sys=0.00, real=0.01 secs]\n"
    )
    (raw,) = ParallelGCParser().parse([line])
    assert raw["young_before"] == 65536
    assert raw["pause"] == 0.01


def test_parallel_old_psoldgen_and_permgen() -> None:
    line = (
        "5.0: [Full GC [PSYoungGen: 100K->0K(200K)] [PSOldGen: 500K->400K(1000K)] "
        "600K->400K(1200K), [PSPermGen: 30K->30K(60K)], 0.2000000 secs]\n"
    )
    (raw,) = ParallelGCParser().parse([line])
    assert raw["gc_kind"] == "Full"
    assert raw["cause"] is None
    assert (raw["old_after"], raw["metaspace_total"]) == (400, 60)


@pytest.mark.parametrize(
    ("line", "kind", "cause"),
    [
        (
            "1.0: [GC (Allocation Failure)  65536K->10008K(251392K), 0.0100000 secs]",
            "Young",
            "Allocation Failure",
        ),
        (
            "2.0: [Full GC (Ergonomics)  20008K->9000K(251392K), 0.0500000 secs]",
            "Full",
            "Ergonomics",
        ),
        (
            "3.0: [Full GC (System.gc())  20008K->9000K(251392K), 0.0500000 secs]",
            "Full",
            "System.gc()",
        ),
    ],
)
def test_print_gc_only_lines(line: str, kind: str, cause: str) -> None:
    lines = ["CommandLine flags: -XX:+PrintGC -XX:+UseParallelGC \n", line + "\n"]
    (event,) = parse_lines(lines)
    assert (event.gc_kind, event.cause) == (kind, cause)
    assert event.old_after_kb is None
    assert event.has_heap_data


def test_print_gc_only_without_flags_line() -> None:
    lines = ["1.0: [GC (Allocation Failure)  65536K->10008K(251392K), 0.0100000 secs]\n"]
    parser = detect_gc_type_and_create_parser(lines)
    assert parser.gc_type_name.startswith("Unknown collector")
    assert len(parser.parse(lines)) == 1


def test_parnew_with_serial_old() -> None:
    lines = [
        "CommandLine flags: -XX:+UseParNewGC \n",
        "1.0: [GC (Allocation Failure) 1.0: [ParNew: 1000K->100K(2000K), 0.01 secs] "
        "5000K->4100K(10000K), 0.0110000 secs]\n",
    ]
    parser = detect_gc_type_and_create_parser(lines)
    assert parser.gc_type_name == "ParNew GC"
    (raw,) = parser.parse(lines)
    assert raw["old_after"] == 4000


def test_cms_full_gc_with_concurrent_mode_interrupted_and_perm() -> None:
    line = (
        "100.0: [Full GC (System.gc()) 100.0: [CMS (concurrent mode interrupted): "
        "500K->400K(1000K), 0.5 secs] 600K->400K(1200K), [CMS Perm : 30K->30K(60K)], "
        "0.5100000 secs]\n"
    )
    (raw,) = GenerationalGCParser().parse([line])
    assert raw["gc_kind"] == "Full"
    assert raw["concurrent_mode_failure"] is False
    assert raw["metaspace_after"] == 30


def test_legacy_record_without_any_stamp() -> None:
    line = "[GC (Allocation Failure) [PSYoungGen: 1K->1K(2K)] 1K->1K(4K), 0.0100000 secs]\n"
    (event,) = parse_lines(["CommandLine flags: -XX:+UseParallelGC \n", line])
    assert event.uptime_seconds is None
    assert not event.wall_clock


def test_g1_legacy_evacuation_failure_detail_line() -> None:
    lines = [
        "1.000: [GC pause (G1 Evacuation Pause) (young), 0.5000000 secs]\n",
        "      [Evacuation Failure: 5.4 ms]\n",
        "   [Eden: 1.0M(1.0M)->0.0B(1.0M) Survivors: 0.0B->0.0B Heap: 9.0M(10.0M)->9.0M(10.0M)]\n",
    ]
    (raw,) = G1LegacyGCParser().parse(lines)
    assert raw["evacuation_failed"] is True
    assert raw["heap_after"] == 9 * 1024


def test_g1_legacy_print_gc_only_header_carries_heap() -> None:
    line = "1.000: [GC pause (G1 Evacuation Pause) (young) 100M->50M(1024M), 0.0200000 secs]\n"
    (raw,) = G1LegacyGCParser().parse([line])
    assert (raw["heap_before"], raw["heap_after"]) == (100 * 1024, 50 * 1024)


def test_g1_legacy_pause_without_detail_keeps_pause() -> None:
    lines = [
        "1.000: [GC pause (G1 Evacuation Pause) (young), 0.0200000 secs]\n",
        "2.000: [GC pause (G1 Evacuation Pause) (young), 0.0300000 secs]\n",
    ]
    events = parse_lines(["CommandLine flags: -XX:+UseG1GC \n", *lines])
    assert [e.pause_time_seconds for e in events] == [0.02, 0.03]
    assert not any(e.has_heap_data for e in events)


# ---------------------------------------------------------------- unified decorators


@pytest.mark.parametrize(
    ("line", "timestamp", "uptime"),
    [
        ("[10.000s][info][gc] x", None, 10.0),
        ("[10,500s][info][gc] x", None, 10.5),
        ("[10000ms][info][gc] x", None, 10.0),
        ("[1577872800000ms][info][gc] x", "2020-01-01T10:00:00+00:00", None),
        ("[10000000000ns][info][gc] x", None, 10.0),
        ("[1577872800000000000ns][info][gc] x", "2020-01-01T10:00:00+00:00", None),
        (
            "[2020-01-01T10:00:00.000+0000][12.5s][1234][5678][info ][gc,heap   ] x",
            "2020-01-01T10:00:00.000+0000",
            12.5,
        ),
    ],
)
def test_unified_decorators(line: str, timestamp: str | None, uptime: float | None) -> None:
    prefix = parse_unified_prefix(line)
    assert prefix is not None
    assert (prefix.timestamp, prefix.uptime) == (timestamp, uptime)
    assert prefix.message == "x"


@pytest.mark.parametrize(
    "line",
    [
        "[10.000s][info][safepoint] x",
        "[10.000s][gc] no level",
        "no decorators",
        "[GC (x) [PSYoungGen: 1K]",
    ],
)
def test_non_unified_lines(line: str) -> None:
    assert parse_unified_prefix(line) is None


@pytest.mark.parametrize(
    ("message", "kind", "cause"),
    [
        ("GC(1) Pause Full (System.gc()) 236M->76M(256M) 400.000ms", "Full", "System.gc()"),
        (
            "GC(1) Pause Young (Prepare Mixed) (G1 Evacuation Pause) 1M->1M(4M) 1ms",
            "Young",
            "G1 Evacuation Pause",
        ),
        (
            "GC(1) Pause Young (Mixed) (G1 Evacuation Pause) 1M->1M(4M) 1ms",
            "Mixed",
            "G1 Evacuation Pause",
        ),
        ("GC(1) Pause Mixed (G1 Evacuation Pause) 1M->1M(4M) 1ms", "Mixed", "G1 Evacuation Pause"),
        (
            "GC(1) Pause Initial Mark (G1 Humongous Allocation) 1M->1M(4M) 1ms",
            "Young",
            "G1 Humongous Allocation",
        ),
        ("GC(1) Pause Young (Normal) 1M->1M(4M) 1ms", "Young", None),
        ("GC(1) Pause Remark 1M->1M(4M) 1ms", "Remark", "G1 Remark"),
        (
            "GC(1) Pause Young (G1 Evacuation Pause) 1024K->512K(4G) 1.5ms",
            "Young",
            "G1 Evacuation Pause",
        ),
    ],
)
def test_unified_g1_pause_kinds_and_causes(message: str, kind: str, cause: str | None) -> None:
    (raw,) = UnifiedGCParser("G1 GC").parse([f"[1.0s][info][gc] {message}\n"])
    assert (raw["gc_kind"], raw["cause"]) == (kind, cause)
    assert raw["humongous_detected"] is ("Humongous" in (cause or ""))


def test_unified_humongous_region_lines_do_not_flag_humongous() -> None:
    lines = [
        "[0.1s][info][gc,init] Heap Region Size: 1M\n",
        "[1.0s][info][gc,heap] GC(0) Humongous regions: 5->5\n",
        "[1.0s][info][gc,heap] GC(0) Old regions: 10->10\n",
        "[1.0s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 50M->20M(100M) 5.0ms\n",
    ]
    (raw,) = UnifiedGCParser().parse(lines)
    assert raw["humongous_detected"] is False
    assert raw["old_after"] == 15 * 1024  # old + humongous regions
    assert raw["old_total"] == 100 * 1024


def test_unified_region_lines_after_pause_and_old_region_size_line() -> None:
    lines = [
        "[0.1s][info][gc,heap] Heap region size: 2M\n",
        "[1.0s][info][gc] GC(0) Pause Young (Normal) (G1 Evacuation Pause) 50M->20M(100M) 5.0ms\n",
        "[1.0s][info][gc,heap] GC(0) Eden regions: 10->0(10)\n",
        "[1.0s][info][gc,heap] GC(0) Survivor regions: 0->2(2)\n",
        "[1.0s][info][gc,heap] GC(0) Old regions: 3->4\n",
        "[1.0s][info][gc,metaspace] GC(0) Metaspace: 100K->100K(1000K)\n",
        "[1.0s][info][gc,heap] GC(7) Old regions: 1->1\n",  # unknown GC id: ignored
    ]
    (raw,) = UnifiedGCParser().parse(lines)
    assert (raw["young_before"], raw["young_after"]) == (20 * 1024, 4 * 1024)
    assert raw["old_after"] == 8 * 1024
    assert raw["metaspace_total"] == 1000


def test_apply_region_counts_without_region_size() -> None:
    event = {"eden_before_regions": 1, "survivor_before_regions": 1}
    apply_region_counts(event)
    assert "young_before" not in event


def test_unified_cms_initial_mark_kind() -> None:
    (raw,) = UnifiedGCParser("CMS GC").parse(
        ["[1.0s][info][gc] GC(1) Pause Initial Mark 5M->5M(9M) 1.0ms\n"]
    )
    assert (raw["gc_kind"], raw["cause"]) == ("Initial Mark", "CMS Initial Mark")


def test_unified_serial_generation_lines() -> None:
    lines = [
        "[0.0s][info][gc] Using Serial\n",
        "[1.0s][info][gc,heap] GC(0) DefNew: 1000K->100K(2000K)\n",
        "[1.0s][info][gc,heap] GC(0) Tenured: 500K->600K(4000K)\n",
        "[1.0s][info][gc] GC(0) Pause Young (Allocation Failure) 1M->1M(6M) 3.000ms\n",
    ]
    parser = detect_gc_type_and_create_parser(lines)
    assert parser.gc_type_name == "Serial GC"
    (raw,) = parser.parse(lines)
    assert (raw["young_after"], raw["old_after"]) == (100, 600)


# ---------------------------------------------------------------- detection


@pytest.mark.parametrize(
    ("flag", "expected"),
    [
        ("-XX:+UseG1GC", "G1 GC"),
        ("-XX:+UseConcMarkSweepGC -XX:+UseParNewGC", "CMS GC"),
        ("-XX:+UseParallelGC", "Parallel GC"),
        ("-XX:+UseParallelOldGC", "Parallel GC"),
        ("-XX:+UseSerialGC", "Serial GC"),
    ],
)
def test_legacy_detection_from_flags(flag: str, expected: str) -> None:
    lines = [f"CommandLine flags: -XX:MaxHeapSize=1 {flag} \n"]
    assert detect_gc_type_and_create_parser(lines).gc_type_name == expected


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("1.0: [GC pause (G1 Evacuation Pause) (young), 0.01 secs]", "G1 GC"),
        ("1.0: [GC (CMS Initial Mark) [1 CMS-initial-mark: 1K(2K)] 1K(4K), 0.01 secs]", "CMS GC"),
        (
            "1.0: [GC (Allocation Failure) 1.0: [DefNew: 1K->1K(2K), 0.01 secs] "
            "1K->1K(4K), 0.01 secs]",
            "Serial GC",
        ),
    ],
)
def test_legacy_detection_from_content(line: str, expected: str) -> None:
    assert detect_gc_type_and_create_parser([line + "\n"]).gc_type_name == expected


def test_unified_rotated_file_defaults_to_g1() -> None:
    lines = ["[5.0s][info][gc] GC(9) Pause Young (Normal) (G1 Evacuation Pause) 5M->1M(9M) 1ms\n"]
    assert detect_gc_type_and_create_parser(lines).gc_type_name == "G1 GC"


# ---------------------------------------------------------------- coverage


def test_g1_worker_detail_lines_are_not_candidates() -> None:
    lines = [
        "1.000: [GC pause (G1 Evacuation Pause) (young), 0.0150000 secs]\n",
        "      [GC Worker Start (ms): Min: 1000.0, Avg: 1000.1]\n",
        "      [GC Worker Other (ms): Min: 0.0]\n",
    ]
    coverage = compute_candidate_coverage(lines, G1LegacyGCParser().parse(lines))
    assert (coverage.candidate_lines, coverage.parsed_candidate_lines) == (1, 1)


def test_coverage_label_prefixes_samples() -> None:
    coverage = compute_candidate_coverage(["1.0: [GC garbled\n"], [], label="gc.log.1")
    assert coverage.unparsed_samples == ["gc.log.1:L1: 1.0: [GC garbled"]


def test_mixed_line_counts() -> None:
    events = parse_lines(
        [
            "[0.0s][info][gc] Using G1\n",
            "[1.0s][info][gc] GC(0) Pause Young (Prepare Mixed) (G1 Evacuation Pause) "
            "5M->1M(9M) 1ms\n",
            "[2.0s][info][gc] GC(1) Pause Young (Mixed) (G1 Evacuation Pause) 5M->1M(9M) 1ms\n",
        ]
    )
    assert kinds(events) == {"Young": 1, "Mixed": 1}
