"""Independent cross-check of gc-analyze's pause counts and totals.

Tallies GC pauses straight from the log with deliberately simple, *different* logic from the
tool's parsers (legacy records are read up to their "[Times:" line instead of balancing
brackets; unified pause lines are matched with one regex), then compares per-kind counts,
total pause time and the longest pause with what gc-analyze reports.

    uv run python scripts/crosscheck.py gc.log [more.log ...]

Exit status is 1 if any number differs.
"""

from __future__ import annotations

import re
import sys
from collections import Counter
from pathlib import Path

from gc_analyze.pipeline import run_analysis

UNIFIED_PAUSE = re.compile(
    r"\]\s*GC\(\d+\) Pause (?P<what>.+?) \d+(?:\.\d+)?[BKMG]->\d+(?:\.\d+)?[BKMG]"
    r"\(\d+(?:\.\d+)?[BKMG]\) (?P<ms>[\d.]+)ms\s*$"
)
LEGACY_START = re.compile(r"^(?:\d{4}-\S+: )?(?:\d+\.\d+: )?\[(?:GC|Full GC)[ (]")
LAST_SECS = re.compile(r"([\d.]+) secs\]")
FULL_START = re.compile(r"^(?:\d{4}-\S+: )?(?:\d+\.\d+: )?\[Full GC")
CONCURRENT = re.compile(r"\[(?:CMS-concurrent|GC concurrent)-[^\]]*\](?:\s*\[Times:[^\]]*\])?")


def complete(record: str) -> bool:
    """A record is complete once, ignoring concurrent phases, it ends in "N secs]"."""
    body = CONCURRENT.sub("", record).split("[Times:")[0].rstrip()
    return body.endswith("secs]")


def unified_kind(what: str, collector_g1: bool) -> str:
    if what.startswith("Full"):
        return "Full"
    if what.startswith("Remark"):
        return "Remark"
    if what.startswith("Cleanup"):
        return "Cleanup"
    if what.startswith("Initial Mark"):
        return "Young" if collector_g1 else "Initial Mark"
    if what.startswith("Mixed") or "(Mixed)" in what:
        return "Mixed"
    return "Young"


def legacy_kind(record: str) -> str:
    if (
        FULL_START.match(record)
        or "[CMS:" in record
        or "[Tenured:" in record
        or "(concurrent mode failure)" in record
    ):
        return "Full"
    if "CMS-initial-mark" in record:
        return "Initial Mark"
    if "CMS-remark" in record or "[GC remark" in record:
        return "Remark"
    if "[GC cleanup" in record:
        return "Cleanup"
    if "(mixed)" in record:
        return "Mixed"
    return "Young"


def tally(path: Path) -> tuple[Counter[str], float, float]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kinds: Counter[str] = Counter()
    pauses: list[float] = []
    g1 = any("Using G1" in line or "G1" in line for line in lines[:200])
    i = 0
    while i < len(lines):
        line = lines[i]
        if match := UNIFIED_PAUSE.search(line):
            kinds[unified_kind(match.group("what"), g1)] += 1
            pauses.append(float(match.group("ms")) / 1000)
        elif LEGACY_START.match(line) and "[GC concurrent" not in line:
            record = line
            # read on until the record is complete (or the next record starts)
            j = i
            while (
                not complete(record) and j + 1 < len(lines) and not LEGACY_START.match(lines[j + 1])
            ):
                j += 1
                record += lines[j]
            before_times = CONCURRENT.sub("", record).split("[Times:")[0]
            values = LAST_SECS.findall(before_times)
            if values and before_times.rstrip().endswith("secs]"):
                kinds[legacy_kind(before_times)] += 1
                pauses.append(float(values[-1]))
            i = j
        i += 1
    return kinds, sum(pauses), max(pauses, default=0.0)


def main(paths: list[str]) -> int:
    failed = False
    for name in paths:
        path = Path(name)
        expected_kinds, expected_sum, expected_max = tally(path)
        result = run_analysis([path], segment="all")
        actual_kinds = Counter(result.summary.counts_by_kind)
        actual_sum = result.summary.total_gc_time_sec
        actual_max = result.summary.overall_pauses.maximum
        ok = (
            expected_kinds == actual_kinds
            and abs(expected_sum - actual_sum) < 1e-6
            and abs(expected_max - actual_max) < 1e-9
        )
        failed |= not ok
        print(f"{'OK  ' if ok else 'DIFF'} {path.name}")
        for kind in sorted(set(expected_kinds) | set(actual_kinds)):
            mark = "" if expected_kinds[kind] == actual_kinds[kind] else "   <-- differs"
            print(
                f"       {kind:<13} independent={expected_kinds[kind]:<7} "
                f"gc-analyze={actual_kinds[kind]}{mark}"
            )
        print(f"       total pause   independent={expected_sum:.6f}s gc-analyze={actual_sum:.6f}s")
        print(f"       longest       independent={expected_max:.6f}s gc-analyze={actual_max:.6f}s")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
