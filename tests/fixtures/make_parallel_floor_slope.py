"""Generate parallel_floor_slope.log: 12 h of Java 8 Parallel GC whose post-Full-GC old-gen
floors rise exactly 50 MB per hour (100 MB at hour 0 ... 700 MB at hour 12).

Run from this directory: python make_parallel_floor_slope.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

START = datetime(2023, 4, 1, 0, 0, 0, tzinfo=timezone(timedelta(hours=-4)))
YOUNG_TOTAL = 262144  # K
OLD_TOTAL = 1048576  # K (1 GB old generation)
HEAP_TOTAL = YOUNG_TOTAL + OLD_TOTAL


def stamp(seconds: float) -> str:
    moment = START + timedelta(seconds=seconds)
    text = moment.strftime("%Y-%m-%dT%H:%M:%S.000%z")
    return f"{text}: {seconds + 30:.3f}:"  # JVM started 30 s before START


def main() -> None:
    lines = [
        "CommandLine flags: -XX:InitialHeapSize=1342177280 -XX:MaxHeapSize=1342177280 "
        "-XX:+PrintGC -XX:+PrintGCDateStamps -XX:+PrintGCDetails -XX:+PrintGCTimeStamps "
        "-XX:+UseParallelGC "
    ]
    old = 102400
    for hour in range(13):
        base = hour * 3600
        # Full GC at hh:00: old gen drops to the floor 100 MB + 50 MB * hour
        floor = 102400 + 51200 * hour
        before = old + 4096
        lines.append(
            f"{stamp(base)} [Full GC (Ergonomics) [PSYoungGen: 4096K->0K({YOUNG_TOTAL}K)] "
            f"[ParOldGen: {old}K->{floor}K({OLD_TOTAL}K)] {before}K->{floor}K({HEAP_TOTAL}K), "
            "[Metaspace: 30000K->30000K(1077248K)], 0.5000000 secs] "
            "[Times: user=1.00 sys=0.00, real=0.50 secs] "
        )
        old = floor
        if hour == 12:
            break
        # five young GCs, every 10 minutes, each promoting 20 MB
        for minute in (10, 20, 30, 40, 50):
            young_before, young_after = 200000, 8192
            promoted = 20480
            heap_before = old + young_before
            old += promoted
            heap_after = old + young_after
            lines.append(
                f"{stamp(base + minute * 60)} [GC (Allocation Failure) [PSYoungGen: "
                f"{young_before}K->{young_after}K({YOUNG_TOTAL}K)] "
                f"{heap_before}K->{heap_after}K({HEAP_TOTAL}K), 0.0200000 secs] "
                "[Times: user=0.04 sys=0.00, real=0.02 secs] "
            )
    Path(__file__).with_name("parallel_floor_slope.log").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
