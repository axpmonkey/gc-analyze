"""JVM flags: CommandLine flags (Java 8), unified startup lines, size arguments."""

from __future__ import annotations

import pytest

from gc_analyze.jvm_config import (
    parse_jvm_heap_config,
    parse_jvm_size_to_bytes,
    parse_max_heap_from_log,
    parse_size_argument,
)
from gc_analyze.report import build_jvm_config_rows

ALL_FLAGS = (
    "CommandLine flags: -XX:InitialHeapSize=1073741824 -XX:MaxHeapSize=4294967296 "
    "-XX:NewSize=536870912 -XX:MaxNewSize=1073741824 -XX:OldSize=536870912 "
    "-XX:MaxRAM=17179869184 -XX:SoftMaxHeapSize=3221225472 -XX:MetaspaceSize=268435456 "
    "-XX:MaxMetaspaceSize=536870912 -XX:MaxDirectMemorySize=1073741824 "
    "-XX:G1HeapRegionSize=4194304 -XX:NewRatio=2 -XX:SurvivorRatio=8 -XX:InitialSurvivorRatio=8 "
    "-XX:TargetSurvivorRatio=50 -XX:MaxTenuringThreshold=15 -XX:MaxHeapFreeRatio=70 "
    "-XX:MinHeapFreeRatio=40 -XX:ParallelGCThreads=8 -XX:ConcGCThreads=2 "
    "-XX:MaxGCPauseMillis=200 -XX:GCTimeRatio=99 -XX:AdaptiveSizePolicyWeight=10 "
    "-XX:InitialRAMPercentage=25 -XX:MinRAMPercentage=50 -XX:MaxRAMPercentage=75 "
    "-XX:MaxRAMFraction=4 -XX:ThreadStackSize=1024 -XX:InitiatingHeapOccupancyPercent=45 "
    "-XX:G1ReservePercent=10 -XX:G1NewSizePercent=5 -XX:G1MaxNewSizePercent=60 "
    "-XX:G1MixedGCCountTarget=8 -XX:G1HeapWastePercent=5 -XX:G1MixedGCLiveThresholdPercent=85 "
    "-XX:G1RSetUpdatingPauseTimePercent=10 -XX:G1OldCSetRegionThresholdPercent=10 "
    "-XX:CMSInitiatingOccupancyFraction=75 -XX:CMSFullGCsBeforeCompaction=1 "
    "-XX:CMSWaitDuration=2000 -XX:+AlwaysPreTouch -XX:+UseAdaptiveSizePolicy "
    "-XX:+UseAdaptiveSizePolicyFootprintGoal -XX:+UseCMSInitiatingOccupancyOnly -XX:+UseG1GC \n"
)


def test_all_commandline_flags_and_rows() -> None:
    config = parse_jvm_heap_config([ALL_FLAGS])
    assert config is not None
    assert config.max_heap_size_bytes == 4 * 1024**3
    assert config.cms_wait_duration == 2000
    assert config.use_cms_initiating_occupancy_only is True
    rows = dict(build_jvm_config_rows(config))
    assert rows["Maximum Heap Size (-Xmx)"] == "4.0G"
    assert rows["G1 Heap Region Size"] == "4.0M"
    assert rows["Always Pre Touch"] == "enabled"
    assert rows["CMS Wait Duration"] == "2000ms"
    assert len(rows) == 44  # 11 size + 29 numeric + 4 boolean flags


@pytest.mark.parametrize(
    ("flags", "field", "value"),
    [
        ("-Xms512m -Xmx2g -Xmn256M", "max_heap_size_bytes", 2 * 1024**3),
        ("-Xms512m -Xmx2g -Xmn256M", "initial_heap_size_bytes", 512 * 1024**2),
        ("-Xms512m -Xmx2g -Xmn256M", "new_size_bytes", 256 * 1024**2),
        ("-Xmx1048576k", "max_heap_size_bytes", 1024**3),
        ("-Xmx1073741824", "max_heap_size_bytes", 1024**3),
    ],
)
def test_short_heap_flags(flags: str, field: str, value: int) -> None:
    config = parse_jvm_heap_config([f"CommandLine flags: {flags} \n"])
    assert config is not None
    assert getattr(config, field) == value


def test_jvm_size_units() -> None:
    assert parse_jvm_size_to_bytes("5", None) == 5
    assert parse_jvm_size_to_bytes("5", "x") == 5
    assert parse_jvm_size_to_bytes("2", "G") == 2 * 1024**3


def test_unified_startup_lines() -> None:
    lines = [
        "[0.0s][info][gc,heap] Heap Region Size: 2M\n",
        "[0.0s][info][gc,heap] Heap region size: 512K\n",
        "[1.0s][info][gc,task] GC(0) Using 3 workers of 8 for evacuation\n",
        "[2.0s][info][gc,task] GC(1) Using 2 workers of 6 for evacuation\n",
    ]
    config = parse_jvm_heap_config(lines)
    assert config is not None
    assert config.g1_heap_region_size_bytes == 512 * 1024  # last stated
    assert config.parallel_gc_threads == 8  # first "of N"
    assert config.max_heap_size_bytes is None
    assert parse_jvm_heap_config(["nothing\n"]) is None
    assert parse_jvm_heap_config(["CommandLine flags: -XX:+PrintGC \n"]) is None


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("[0.0s][info][gc,init] Heap Max Capacity: 3G", 3 * 1024**3),
        ("[0.0s][info][gc,init] Heap Max Capacity: 512M", 512 * 1024**2),
        (
            "[0.0s][info][gc,heap,coops] Heap address: 0x0000000740000000, size: 3072 MB, x",
            3 * 1024**3,
        ),
        ("[0.0s][info][gc,heap] Heap region size: 1M", None),
        ("unrelated", None),
    ],
)
def test_max_heap_from_log(line: str, expected: int | None) -> None:
    assert parse_max_heap_from_log([line]) == expected


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("4g", 4 * 1024**3),
        ("3072m", 3 * 1024**3),
        ("1024", 1024),
        ("1.5G", int(1.5 * 1024**3)),
        ("512KB", 512 * 1024),
    ],
)
def test_size_argument(text: str, value: int) -> None:
    assert parse_size_argument(text) == value


def test_size_argument_rejects_garbage() -> None:
    with pytest.raises(ValueError, match="not a size"):
        parse_size_argument("lots")
