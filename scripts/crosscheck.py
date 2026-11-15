"""Independent cross-check of gc-analyze's pause counts and totals.

Tallies GC pauses straight from the log with deliberately simple, *different* logic from the
tool's parsers (legacy records are read up to their "[Times:" line instead of balancing
brackets; unified pause lines are matched with one regex), then compares per-kind counts,
total pause time, the longest pause, and the summed whole-heap sizes before and after each
pause with what gc-analyze reports.

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
    r"\]\s*GC\(\d+\) Pause (?P<what>.+?) (?P<hb>\d+(?:\.\d+)?[BKMG])->"
    r"(?P<ha>\d+(?:\.\d+)?[BKMG])\(\d+(?:\.\d+)?[BKMG]\) (?P<ms>[\d.]+)ms\s*$"
)
# Whole-heap transition of a legacy record: the last "NK->NK(NK)" (or M/G for G1) that is
# followed by the record's own ", N secs]" or by a metaspace block.
LEGACY_HEAP = re.compile(
    r"(?P<hb>\d+(?:\.\d+)?[BKMG])->(?P<ha>\d+(?:\.\d+)?[BKMG])\(\d+(?:\.\d+)?[BKMG]\)"
    r"(?=,? *(?:\[Metaspace|\[PSPermGen|\[CMS Perm|\[Perm|[\d.]+ secs\]$))"
)
# CMS initial-mark / remark log one occupancy, not a transition:
# "] 10887844K(12514816K), 0.0001997 secs]"
CMS_MARK_HEAP = re.compile(r"\]\s*(?P<used>\d+K)\(\d+K\), [\d.]+ secs\]$")
# Java 8 G1 with PrintGCDetails puts the heap transition on an indented detail line
G1_DETAIL_HEAP = re.compile(
    r"Heap: (?P<hb>\d+(?:\.\d+)?[BKMG])\(\d+(?:\.\d+)?[BKMG]\)->(?P<ha>\d+(?:\.\d+)?[BKMG])\("
)
UNIT_KB = {"B": 1 / 1024, "K": 1, "M": 1024, "G": 1024 * 1024}


def to_kb(size: str) -> int:
    """Size token to whole KB, truncating like the JVM's own rounding to the unit shown."""
    return int(float(size[:-1]) * UNIT_KB[size[-1]])


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


def tally(path: Path) -> tuple[Counter[str], float, float, int, int]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    kinds: Counter[str] = Counter()
    pauses: list[float] = []
    heap_before_kb = heap_after_kb = 0
    g1 = any("Using G1" in line or "G1" in line for line in lines[:200])
    i = 0
    while i < len(lines):
        line = lines[i]
        if match := UNIFIED_PAUSE.search(line):
            kinds[unified_kind(match.group("what"), g1)] += 1
            pauses.append(float(match.group("ms")) / 1000)
            heap_before_kb += to_kb(match.group("hb"))
            heap_after_kb += to_kb(match.group("ha"))
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
                body = before_times.rstrip()
                detail = None
                for following in lines[j + 1 :]:
                    if not following.startswith(" "):
                        break
                    if detail := G1_DETAIL_HEAP.search(following):
                        break
                heaps = LEGACY_HEAP.findall(body)
                if detail:
                    heap_before_kb += to_kb(detail.group("hb"))
                    heap_after_kb += to_kb(detail.group("ha"))
                elif "CMS-initial-mark" in body or "CMS-remark" in body:
                    if mark := CMS_MARK_HEAP.search(body):
                        heap_before_kb += to_kb(mark.group("used"))
                        heap_after_kb += to_kb(mark.group("used"))
                elif heaps:
                    heap_before_kb += to_kb(heaps[-1][0])
                    heap_after_kb += to_kb(heaps[-1][1])
            i = j
        i += 1
    return kinds, sum(pauses), max(pauses, default=0.0), heap_before_kb, heap_after_kb


def main(paths: list[str]) -> int:
    failed = False
    for name in paths:
        path = Path(name)
        expected_kinds, expected_sum, expected_max, expected_before, expected_after = tally(path)
        result = run_analysis([path], segment="all")
        actual_kinds = Counter(result.summary.counts_by_kind)
        actual_sum = result.summary.total_gc_time_sec
        actual_max = result.summary.overall_pauses.maximum
        actual_before = sum(e.heap_before_kb for e in result.events if e.has_heap_data)
        actual_after = sum(e.heap_after_kb for e in result.events if e.has_heap_data)
        ok = (
            expected_kinds == actual_kinds
            and abs(expected_sum - actual_sum) < 1e-6
            and abs(expected_max - actual_max) < 1e-9
            and expected_before == actual_before
            and expected_after == actual_after
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
        print(f"       heap before   independent={expected_before}K gc-analyze={actual_before}K")
        print(f"       heap after    independent={expected_after}K gc-analyze={actual_after}K")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
