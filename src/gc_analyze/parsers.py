"""Collector-specific GC log parsers and format/collector detection.

Every parser turns log lines into raw event dicts (see ``RawEvent``) that
``events.normalize_event`` validates into ``GCEvent``. Keys used:

    timestamp (str | None), uptime (float | None), gc_kind, pause (s), cause,
    heap_before/heap_after/heap_total (KB), young_*/old_* (KB), metaspace_* (KB),
    humongous_detected, evacuation_failed, to_space_exhausted, concurrent_start,
    humongous_before/humongous_after (KB), promoted (KB),
    concurrent_mode_failure, promotion_failed,
    line_index (0-based first line of the record), line_end (0-based last line)

Two log families exist:

* Legacy (Java 8 and earlier, ``-XX:+PrintGCDetails``): one record per collection, sometimes
  spread over several physical lines (tenuring tables, interleaved concurrent phases,
  ``PrintAdaptiveSizePolicy``). ``iter_legacy_records`` joins and cleans those first.
* Unified (JDK 9+, ``-Xlog:gc*``): one ``Pause ...`` line per collection with detail lines
  linked by ``GC(n)``; the pause-line layout is shared by all collectors.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any, Protocol

from .events import parse_log_timestamp, parse_size_to_kb
from .models import SideRecord

RawEvent = dict[str, Any]


class GCParser(Protocol):
    """Protocol defining GC parser interface."""

    gc_type_name: str
    log_family: str  # "legacy" or "unified"

    def parse(self, log_lines: list[str]) -> list[RawEvent]:
        """Parse raw log lines into event dictionaries."""
        ...


# ============================================================
# SHARED PIECES
# ============================================================

# A parenthesised group allowing one level of nesting: "(System.gc())", "(Allocation Failure)"
PAREN_GROUP = r"\((?:[^()]|\([^()]*\))*\)"
_PAREN_GROUP_RE = re.compile(PAREN_GROUP)
# A JVM running under a decimal-comma locale writes "10,000: [GC ... 0,0301000 secs]", so
# every number that can carry a fraction accepts either separator.
DEC = r"\d+(?:[.,]\d+)?"
LEGACY_DATE = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{4}|Z)?"
SIZE = r"\d+(?:[.,]\d+)?[BKMG]"


def to_float(text: str) -> float:
    """Number as logged, with "." or "," as the decimal separator."""
    return float(text.replace(",", "."))


def paren_contents(text: str) -> list[str]:
    """Inner text of each top-level (...) group: "(a) (b(c))" -> ["a", "b(c)"]."""
    return [m.group(0)[1:-1].strip() for m in _PAREN_GROUP_RE.finditer(text)]


def _new_event(**fields: Any) -> RawEvent:
    event: RawEvent = {
        "humongous_detected": False,
        "evacuation_failed": False,
        "to_space_exhausted": False,
        "concurrent_mode_failure": False,
        "promotion_failed": False,
        "concurrent_start": False,
    }
    event.update(fields)
    return event


def _metaspace(event: RawEvent, match: re.Match[str] | None) -> None:
    if match is not None and match.group("mb") is not None:
        event["metaspace_before"] = int(match.group("mb"))
        event["metaspace_after"] = int(match.group("ma"))
        event["metaspace_total"] = int(match.group("mt"))


# ============================================================
# LEGACY (JAVA 8) RECORDS
# ============================================================

# Record prefix: optional datestamp (-XX:+PrintGCDateStamps), optional uptime
# (-XX:+PrintGCTimeStamps). Anchored at the start of the record.
LEGACY_STAMP_RE: re.Pattern[str] = re.compile(
    rf"^\s*(?:(?P<timestamp>{LEGACY_DATE}):\s+)?(?:(?P<uptime>\d+[.,]\d+):\s+)?"
)
# A legacy GC record starts at column 0 with "[GC" / "[Full GC" after the stamp. Indented
# lines ("      [GC Worker Start (ms): ...") are G1 details, and "[GC concurrent-*" are G1
# concurrent-phase notes, not pauses.
LEGACY_RECORD_START: re.Pattern[str] = re.compile(
    rf"^(?:{LEGACY_DATE}:\s+)?(?:\d+[.,]\d+:\s+)?\[(?:Full GC|GC(?! concurrent-))\b"
)
_INNER_STAMP = rf"(?:{LEGACY_DATE}:\s*)?(?:\d+[.,]\d+:\s*)?"
# Text that appears inside a record but carries no pause data; removed before matching.
LEGACY_NOISE: tuple[re.Pattern[str], ...] = (
    # -XX:+PrintTenuringDistribution table lines (whole physical lines)
    re.compile(r"^Desired survivor size .*$|^- age +\d+:.*$", re.MULTILINE),
    # Concurrent phases interleaved into a pause record (CMS and G1)
    re.compile(rf"{_INNER_STAMP}\[CMS-concurrent-[^\]]*\](?:\s*\[Times:[^\]]*\])?"),
    re.compile(rf"{_INNER_STAMP}\[GC concurrent-[^\]]*\]"),
    # -XX:+PrintAdaptiveSizePolicy (G1)
    re.compile(rf"\s*{_INNER_STAMP}\[G1Ergonomics[^\]]*\]"),
    # -XX:+PrintReferenceGC
    re.compile(rf"{_INNER_STAMP}\[(?:Soft|Weak|Final|Phantom|JNI Weak )Reference,[^\]]*\]"),
    # Times are not used (the pause is the "N secs]" figure)
    re.compile(r"\s*\[Times:[^\]]*\]"),
)
MAX_CONTINUATION_LINES = 40
LEGACY_TIMES_RE: re.Pattern[str] = re.compile(
    rf"\[Times: user=(?P<user>{DEC}) sys=(?P<sys>{DEC}),? real=(?P<real>{DEC}) secs\]"
)
# Concurrent phases carry their own [Times: ...]; they are not the pause's CPU time
_CONCURRENT_WITH_TIMES = re.compile(r"\[CMS-concurrent-[^\]]*\]\s*\[Times:[^\]]*\]")
MAX_TIMES_LOOKAHEAD_LINES = 80


# -XX:+PrintHeapAtGC block printed after each collection:
#   "Heap after GC invocations=7 (full 1):" ... "  from space 30720K, 99% used [...]" ... "}"
_HEAP_AFTER_GC = "Heap after GC"
_FROM_SPACE_RE = re.compile(r"^\s*from space (?P<capacity>\d+)K,\s*(?P<used>\d+)% used")
MAX_HEAP_AFTER_GC_LINES = 16


def legacy_survivor_after_gc(log_lines: list[str], end: int) -> dict[str, float]:
    """Survivor ("from space") capacity and occupancy after the record ending on line ``end``.

    Only read from the "Heap after GC" block that directly follows the record.
    """
    in_block = False
    for line in log_lines[end + 1 : end + 1 + MAX_HEAP_AFTER_GC_LINES]:
        if not in_block:
            if line.startswith(_HEAP_AFTER_GC):
                in_block = True
            elif line.strip() and not line[:1].isspace():
                break  # another record or block came first
            continue
        if line.startswith("}"):
            break
        if match := _FROM_SPACE_RE.match(line):
            return {
                "survivor_capacity": int(match.group("capacity")),
                "survivor_used_pct": float(match.group("used")),
            }
    return {}


def legacy_cpu_times(log_lines: list[str], start: int, end: int) -> dict[str, float]:
    """user/sys/real of the record on lines ``start``..``end`` (0-based), if it logs them.

    The figure normally closes the record's own line. Java 8 G1 with PrintGCDetails prints it
    on an indented line after the detail lines, so indented lines after ``end`` are searched
    too.
    """
    found: re.Match[str] | None = None
    last = min(len(log_lines), end + 1 + MAX_TIMES_LOOKAHEAD_LINES)
    for index in range(start, last):
        line = log_lines[index]
        if index > end and not line[:1].isspace():
            break
        matches = list(LEGACY_TIMES_RE.finditer(_CONCURRENT_WITH_TIMES.sub("", line)))
        if matches:
            found = matches[-1]
            if index > end:
                break
    if found is None:
        return {}
    return {
        "cpu_user": to_float(found.group("user")),
        "cpu_sys": to_float(found.group("sys")),
        "cpu_real": to_float(found.group("real")),
    }


def clean_legacy_record(text: str) -> str:
    """Strip interleaved non-pause fragments from a joined legacy record."""
    for pattern in LEGACY_NOISE:
        text = pattern.sub("", text)
    return text.replace("\n", "")


def iter_legacy_records(log_lines: list[str]) -> Iterator[tuple[int, int, str]]:
    """Yield (first_line_index, last_line_index, cleaned_text) for each legacy GC record.

    A record whose brackets are unbalanced at the end of its first line continues on the
    following lines until they balance (or a new record starts).
    """
    index = 0
    total = len(log_lines)
    while index < total:
        line = log_lines[index].rstrip("\r\n")
        if not LEGACY_RECORD_START.match(line):
            index += 1
            continue
        start = index
        parts = [line]
        depth = line.count("[") - line.count("]")
        while depth > 0 and index + 1 < total and index - start < MAX_CONTINUATION_LINES:
            nxt = log_lines[index + 1].rstrip("\r\n")
            if LEGACY_RECORD_START.match(nxt):
                break
            index += 1
            parts.append(nxt)
            depth += nxt.count("[") - nxt.count("]")
        yield start, index, clean_legacy_record("\n".join(parts))
        index += 1


def _legacy_stamp(text: str) -> tuple[str | None, float | None, str]:
    match = LEGACY_STAMP_RE.match(text)
    assert match is not None  # pattern can match the empty string
    uptime = match.group("uptime")
    return match.group("timestamp"), to_float(uptime) if uptime else None, text[match.end() :]


_CAUSE = r"(?:\s*\((?P<cause>(?:[^()]|\([^()]*\))*)\))?"
_LEGACY_TAIL = (
    r"(?P<hb>\d+)K->(?P<ha>\d+)K\((?P<ht>\d+)K\)"
    r"(?:,\s*\[(?:Metaspace|PSPermGen|CMS Perm|Perm)\s*:\s+"
    r"(?P<mb>\d+)K->(?P<ma>\d+)K\((?P<mt>\d+)K\)\])?"
    rf",\s+(?P<pause>{DEC})\s+secs\]"
)

# -XX:+PrintGC without details: "[GC (Allocation Failure)  65536K->10008K(251392K), 0.01 secs]"
LEGACY_HEAP_ONLY_RE: re.Pattern[str] = re.compile(
    rf"^\[(?P<full>Full GC|GC){_CAUSE}\s*(?P<promo>--)?\s*{_LEGACY_TAIL}"
)


class _LegacyParserBase:
    log_family: str = "legacy"
    gc_type_name: str = ""

    def parse(self, log_lines: list[str]) -> list[RawEvent]:
        """Parse every legacy record into raw events."""
        events: list[RawEvent] = []
        for start, end, text in iter_legacy_records(log_lines):
            timestamp, uptime, rest = _legacy_stamp(text)
            event = self._parse_record(rest)
            if event is None:
                continue
            event.update(timestamp=timestamp, uptime=uptime, line_index=start, line_end=end)
            event.update(legacy_cpu_times(log_lines, start, end))
            event.update(legacy_survivor_after_gc(log_lines, end))
            events.append(event)
        return events

    def _parse_record(self, rest: str) -> RawEvent | None:
        raise NotImplementedError

    @staticmethod
    def _heap_only(rest: str) -> RawEvent | None:
        match = LEGACY_HEAP_ONLY_RE.match(rest)
        if match is None:
            return None
        event = _new_event(
            gc_kind="Full" if match.group("full") == "Full GC" else "Young",
            cause=match.group("cause"),
            pause=to_float(match.group("pause")),
            heap_before=int(match.group("hb")),
            heap_after=int(match.group("ha")),
            heap_total=int(match.group("ht")),
            promotion_failed=match.group("promo") is not None,
        )
        _metaspace(event, match)
        return event


# ---------------------------------------------------------------- Parallel


class ParallelGCParser(_LegacyParserBase):
    """Java 8 Parallel GC (PSYoungGen / ParOldGen or PSOldGen)."""

    gc_type_name: str = "Parallel GC"

    RECORD_RE: re.Pattern[str] = re.compile(
        rf"^\[(?P<full>Full GC|GC){_CAUSE}\s*(?P<promo>--)?\s*"
        r"\[PSYoungGen:\s+(?P<yb>\d+)K->(?P<ya>\d+)K\((?P<yt>\d+)K\)\]\s*"
        r"(?:\[(?:ParOldGen|PSOldGen):\s+(?P<ob>\d+)K->(?P<oa>\d+)K\((?P<ot>\d+)K\)\]\s*)?"
        + _LEGACY_TAIL
    )

    def _parse_record(self, rest: str) -> RawEvent | None:
        match = self.RECORD_RE.match(rest)
        if match is None:
            return self._heap_only(rest)
        young = (int(match.group("yb")), int(match.group("ya")), int(match.group("yt")))
        heap = (int(match.group("hb")), int(match.group("ha")), int(match.group("ht")))
        if match.group("ob") is not None:
            old = (int(match.group("ob")), int(match.group("oa")), int(match.group("ot")))
        else:
            old = validate_old_gen_values(*heap, *young)
        event = _new_event(
            gc_kind="Full" if match.group("full") == "Full GC" else "Young",
            cause=match.group("cause"),
            pause=to_float(match.group("pause")),
            heap_before=heap[0],
            heap_after=heap[1],
            heap_total=heap[2],
            young_before=young[0],
            young_after=young[1],
            young_total=young[2],
            old_before=old[0],
            old_after=old[1],
            old_total=old[2],
            # "[GC (Allocation Failure) --[PSYoungGen:" marks a promotion failure
            promotion_failed=match.group("promo") is not None,
        )
        _metaspace(event, match)
        return event


# ---------------------------------------------------------------- CMS / Serial / ParNew


class GenerationalGCParser(_LegacyParserBase):
    """Java 8 CMS (ParNew + CMS), Serial (DefNew + Tenured) and ParNew + Serial Old.

    A young collection that falls back to collecting the old generation in the same pause
    ("[ParNew (promotion failed): ...][CMS: ...]" or "[CMS (concurrent mode failure): ...]")
    is reported as a Full GC with the failure flag set.
    """

    def __init__(self, gc_type_name: str = "CMS GC") -> None:
        self.gc_type_name = gc_type_name

    RECORD_RE: re.Pattern[str] = re.compile(
        rf"^\[(?P<full>Full GC|GC){_CAUSE}\s*"
        rf"(?:{_INNER_STAMP}\[(?P<ygen>ParNew|DefNew)\s*(?:\((?P<yflag>[^)]*)\))?:\s+"
        r"(?P<yb>\d+)K->(?P<ya>\d+)K\((?P<yt>\d+)K\),\s+[\d.,]+\s+secs\]\s*)?"
        rf"(?:{_INNER_STAMP}\[(?P<ogen>CMS|Tenured)\s*(?:\((?P<oflag>[^)]*)\))?:\s+"
        r"(?P<ob>\d+)K->(?P<oa>\d+)K\((?P<ot>\d+)K\),\s+[\d.,]+\s+secs\]\s*)?" + _LEGACY_TAIL
    )
    INITIAL_MARK_RE: re.Pattern[str] = re.compile(
        r"^\[GC\s*(?:\(CMS Initial Mark\)\s*)?\[1 CMS-initial-mark:\s+"
        r"(?P<oa>\d+)K\((?P<ot>\d+)K\)\]\s*(?P<ha>\d+)K\((?P<ht>\d+)K\),\s+"
        rf"(?P<pause>{DEC})\s+secs\]"
    )
    REMARK_RE: re.Pattern[str] = re.compile(
        r"^\[GC\s*(?:\(CMS Final Remark\))?.*\[1 CMS-remark:\s+"
        r"(?P<oa>\d+)K\((?P<ot>\d+)K\)\]\s*(?P<ha>\d+)K\((?P<ht>\d+)K\),\s+"
        rf"(?P<pause>{DEC})\s+secs\]"
    )

    def _parse_record(self, rest: str) -> RawEvent | None:
        for kind, pattern in (("Initial Mark", self.INITIAL_MARK_RE), ("Remark", self.REMARK_RE)):
            if match := pattern.match(rest):
                heap_after, heap_total = int(match.group("ha")), int(match.group("ht"))
                old_after, old_total = int(match.group("oa")), int(match.group("ot"))
                return _new_event(
                    gc_kind=kind,
                    cause="CMS Initial Mark" if kind == "Initial Mark" else "CMS Final Remark",
                    pause=to_float(match.group("pause")),
                    # these phases log occupancy, not a before->after transition
                    heap_before=heap_after,
                    heap_after=heap_after,
                    heap_total=heap_total,
                    old_before=old_after,
                    old_after=old_after,
                    old_total=old_total,
                )

        match = self.RECORD_RE.match(rest)
        if match is None:
            return self._heap_only(rest)

        yflag = (match.group("yflag") or "").lower()
        oflag = (match.group("oflag") or "").lower()
        has_old = match.group("ob") is not None
        has_young = match.group("yb") is not None
        heap = (int(match.group("hb")), int(match.group("ha")), int(match.group("ht")))
        young: tuple[int, int, int] | None = None
        if has_young:
            young = (int(match.group("yb")), int(match.group("ya")), int(match.group("yt")))
        event = _new_event(
            # an old-generation collection inside the pause makes it a full collection
            gc_kind="Full" if match.group("full") == "Full GC" or has_old else "Young",
            cause=match.group("cause"),
            pause=to_float(match.group("pause")),
            heap_before=heap[0],
            heap_after=heap[1],
            heap_total=heap[2],
            promotion_failed="promotion failed" in yflag,
            concurrent_mode_failure="concurrent mode failure" in oflag,
        )
        if young is not None:
            event.update(young_before=young[0], young_after=young[1], young_total=young[2])
        if has_old:
            event.update(
                old_before=int(match.group("ob")),
                old_after=int(match.group("oa")),
                old_total=int(match.group("ot")),
            )
        elif young is not None:
            old = validate_old_gen_values(*heap, *young)
            event.update(old_before=old[0], old_after=old[1], old_total=old[2])
        _metaspace(event, match)
        return event


# Backwards-compatible name
CMSGCParser = GenerationalGCParser


# ---------------------------------------------------------------- G1 (Java 8)


class G1LegacyGCParser:
    """Java 8 G1: a pause header line, then (with PrintGCDetails) detail lines.

    The heap transition comes from the "[Eden: ... Heap: ...]" detail line, or from the
    header itself when only -XX:+PrintGC is on.
    """

    gc_type_name: str = "G1 GC"
    log_family: str = "legacy"

    PAUSE_RE: re.Pattern[str] = re.compile(
        rf"^\[GC pause\s*(?P<tags>(?:{PAREN_GROUP}\s*)+)"
        rf"(?:(?P<hb>{SIZE})->(?P<ha>{SIZE})\((?P<ht>{SIZE})\))?,?\s+"
        rf"(?P<pause>{DEC})\s+secs\]"
    )
    FULL_RE: re.Pattern[str] = re.compile(
        rf"^\[Full GC{_CAUSE}\s+(?P<hb>{SIZE})->(?P<ha>{SIZE})\((?P<ht>{SIZE})\),\s+"
        rf"(?P<pause>{DEC})\s+secs\]"
    )
    # Greedy ".*": sub-phases ("[Finalize Marking, 0.0001 secs]") come first; the remark
    # total is the last ", N secs]".
    REMARK_RE: re.Pattern[str] = re.compile(rf"^\[GC remark\b.*,\s+(?P<pause>{DEC})\s+secs\]")
    CLEANUP_RE: re.Pattern[str] = re.compile(
        rf"^\[GC cleanup\s+(?P<hb>{SIZE})->(?P<ha>{SIZE})\((?P<ht>{SIZE})\),\s+"
        rf"(?P<pause>{DEC})\s+secs\]"
    )
    DETAIL_RE: re.Pattern[str] = re.compile(
        rf"\[Eden:\s+(?P<eb>{SIZE})\((?P<et>{SIZE})\)->(?P<ea>{SIZE})\({SIZE}\)\s+"
        rf"Survivors:\s+(?P<sb>{SIZE})->(?P<sa>{SIZE})\s+"
        rf"Heap:\s+(?P<hb>{SIZE})\((?P<ht>{SIZE})\)->(?P<ha>{SIZE})\({SIZE}\)\]"
        r"(?:,\s*\[Metaspace:\s+(?P<mb>\d+)K->(?P<ma>\d+)K\((?P<mt>\d+)K\)\])?"
    )

    def parse(self, log_lines: list[str]) -> list[RawEvent]:
        """Parse Java 8 G1 records, attaching detail lines to the preceding pause."""
        events: list[RawEvent] = []
        records = {start: (end, text) for start, end, text in iter_legacy_records(log_lines)}
        pending: RawEvent | None = None  # header seen, waiting for its detail line

        for index, line in enumerate(log_lines):
            if index in records:
                end, text = records[index]
                event = self._parse_record(text)
                if event is not None:
                    event.update(line_index=index, line_end=end)
                    event.update(legacy_cpu_times(log_lines, index, end))
                    events.append(event)
                    pending = event
                continue
            if pending is not None and "[Eden:" in line and (detail := self.DETAIL_RE.search(line)):
                self._apply_detail(pending, detail)
                pending = None
            elif pending is not None and "Evacuation Failure" in line:
                pending["evacuation_failed"] = True  # "      [Evacuation Failure: 5.4 ms]"
        return events

    def _parse_record(self, text: str) -> RawEvent | None:
        timestamp, uptime, rest = _legacy_stamp(text)
        stamp = {"timestamp": timestamp, "uptime": uptime}
        if match := self.PAUSE_RE.match(rest):
            tags = paren_contents(match.group("tags"))
            cause = tags[0] if tags else None
            to_space = any(tag.startswith("to-space") for tag in tags)
            event = _new_event(
                **stamp,
                gc_kind="Mixed" if "mixed" in tags else "Young",
                cause=cause,
                pause=to_float(match.group("pause")),
                humongous_detected=cause is not None and "Humongous" in cause,
                to_space_exhausted=to_space,
                evacuation_failed=to_space,
                concurrent_start="initial-mark" in tags,
            )
            if match.group("hb") is not None:
                self._apply_heap(event, match)
            return event
        if match := self.FULL_RE.match(rest):
            event = _new_event(
                **stamp,
                gc_kind="Full",
                cause=match.group("cause"),
                pause=to_float(match.group("pause")),
            )
            self._apply_heap(event, match)
            return event
        if match := self.REMARK_RE.match(rest):
            return _new_event(
                **stamp,
                gc_kind="Remark",
                cause="G1 Remark",
                pause=to_float(match.group("pause")),
            )
        if match := self.CLEANUP_RE.match(rest):
            event = _new_event(
                **stamp,
                gc_kind="Cleanup",
                cause="G1 Cleanup",
                pause=to_float(match.group("pause")),
            )
            self._apply_heap(event, match)
            return event
        return None

    @staticmethod
    def _apply_heap(event: RawEvent, match: re.Match[str]) -> None:
        event["heap_before"] = parse_size_to_kb(match.group("hb"))
        event["heap_after"] = parse_size_to_kb(match.group("ha"))
        event["heap_total"] = parse_size_to_kb(match.group("ht"))

    def _apply_detail(self, event: RawEvent, match: re.Match[str]) -> None:
        self._apply_heap(event, match)
        young_before = parse_size_to_kb(match.group("eb")) + parse_size_to_kb(match.group("sb"))
        young_after = parse_size_to_kb(match.group("ea")) + parse_size_to_kb(match.group("sa"))
        event["young_before"] = young_before
        event["young_after"] = young_after
        event["old_before"] = max(0, event["heap_before"] - young_before)
        event["old_after"] = max(0, event["heap_after"] - young_after)
        _metaspace(event, match)


# ============================================================
# UNIFIED LOGGING (JDK 9+)
# ============================================================

UNIFIED_LEVELS: frozenset[str] = frozenset({"trace", "debug", "info", "warning", "error"})
_DECORATOR_RE = re.compile(r"\[([^\]]*)\]")
_ISO_DECORATOR_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
_UPTIME_S_RE = re.compile(r"^(\d+(?:[.,]\d+)?)s$")
_MS_RE = re.compile(r"^(\d+)ms$")
_NS_RE = re.compile(r"^(\d+)ns$")
# epoch milliseconds (timemillis) vs. uptime milliseconds (uptimemillis): a JVM up for more
# than ~3 years is not plausible, so values above this are wall-clock
_EPOCH_MS_FLOOR = 10**11
# Messages accepted from lines written without the tags decorator (-Xlog:gc*:file=x:time)
_UNDECORATED_GC_MESSAGE = re.compile(
    r"^(?:GC\(\d+\) |Using (?:G1|Parallel|Serial|Concurrent Mark Sweep|The Z Garbage Collector"
    r"|Shenandoah|Epsilon)\b|Heap [Rr]egion [Ss]ize:|Heap Max Capacity:|Heap address:)"
)
# Lines from different threads can be written a few ms out of order; a real restart goes back
# to (nearly) zero
_UPTIME_RESTART_TOLERANCE_SECONDS = 1.0


class UnifiedPrefix:
    """Decorators of a unified-logging line."""

    __slots__ = ("level", "message", "tags", "timestamp", "uptime")

    def __init__(
        self,
        timestamp: str | None,
        uptime: float | None,
        level: str | None,
        tags: str,
        message: str,
    ) -> None:
        self.timestamp = timestamp
        self.uptime = uptime
        self.level = level
        self.tags = tags
        self.message = message


def parse_unified_prefix(line: str) -> UnifiedPrefix | None:
    """Split "[decorator]...[level][gc,tags] message" into its parts.

    Handles any decorator set: time/utctime (ISO), uptime ("10.000s"), uptimemillis /
    timemillis ("123ms"), uptimenanos/timenanos ("123ns"), pid/tid, level (padded or not).
    The level and tags decorators are optional: a line with a time decorator and a GC message
    ("GC(n) ...", "Using G1", heap sizing) is accepted without them.
    Returns None for lines that are not GC unified log lines.
    """
    position = 0
    timestamp: str | None = None
    uptime: float | None = None
    level: str | None = None
    tags: str | None = None
    while position < len(line) and line[position] == "[":
        match = _DECORATOR_RE.match(line, position)
        if match is None:
            break
        value = match.group(1).strip()
        position = match.end()
        if _ISO_DECORATOR_RE.match(value):
            timestamp = value
        elif m := _UPTIME_S_RE.match(value):
            uptime = float(m.group(1).replace(",", "."))
        elif m := _MS_RE.match(value):
            number = int(m.group(1))
            if number >= _EPOCH_MS_FLOOR:
                timestamp = datetime.fromtimestamp(number / 1000, tz=UTC).isoformat()
            else:
                uptime = number / 1000
        elif m := _NS_RE.match(value):
            number = int(m.group(1))
            if number >= _EPOCH_MS_FLOOR * 10**6:
                timestamp = datetime.fromtimestamp(number / 1e9, tz=UTC).isoformat()
            else:
                uptime = number / 1e9
        elif value in UNIFIED_LEVELS:
            level = value
        elif value.startswith("gc"):
            tags = value
            break  # tags are the last decorator before the message
    message = line[position:].strip()
    if tags is None:
        if (timestamp is None and uptime is None) or not _UNDECORATED_GC_MESSAGE.match(message):
            return None
        tags = ""
    return UnifiedPrefix(timestamp, uptime, level, tags, message)


def parse_unified_prefix_times(line: str) -> tuple[str | None, float | None]:
    """(datestamp, uptime seconds) from the leading decorators of any unified line."""
    timestamp: str | None = None
    uptime: float | None = None
    position = 0
    while position < len(line) and line[position] == "[":
        match = _DECORATOR_RE.match(line, position)
        if match is None:
            break
        value = match.group(1).strip()
        position = match.end()
        if _ISO_DECORATOR_RE.match(value):
            timestamp = value
        elif m := _UPTIME_S_RE.match(value):
            uptime = float(m.group(1).replace(",", "."))
    return timestamp, uptime


UNIFIED_PAUSE_RE: re.Pattern[str] = re.compile(
    r"^GC\((?P<gc_id>\d+)\)\s+Pause\s+(?P<type>Young|Mixed|Full|Initial Mark|Remark|Cleanup)\b"
    rf"\s*(?P<tags>(?:{PAREN_GROUP}\s*)*)"
    rf"(?:(?P<hb>{SIZE})->(?P<ha>{SIZE})\((?P<ht>{SIZE})\)\s+)?"
    rf"(?P<pause>{DEC})\s*ms$"
)
# Tags that describe the young-pause phase, not the cause
G1_YOUNG_PHASE_TAGS: frozenset[str] = frozenset(
    {"Normal", "Concurrent Start", "Prepare Mixed", "Mixed", "Initial Mark"}
)
UNIFIED_REGION_SIZE_RE: re.Pattern[str] = re.compile(
    r"Heap [Rr]egion [Ss]ize:\s+(?P<size>\d+)(?P<unit>[KMG])"
)
UNIFIED_REGION_COUNTS_RE: re.Pattern[str] = re.compile(
    r"^GC\((?P<gc_id>\d+)\)\s+(?P<region>Eden|Survivor|Old|Archive|Humongous) regions:\s+"
    r"(?P<before>\d+)->(?P<after>\d+)(?:\((?P<total>\d+)\))?"
)
# JDK 11: "PSYoungGen: 65536K->10000K(76288K)"; JDK 17+: "65536K(76288K)->10000K(76288K)"
UNIFIED_GENERATION_RE: re.Pattern[str] = re.compile(
    r"^GC\((?P<gc_id>\d+)\)\s+(?P<gen>PSYoungGen|ParOldGen|PSOldGen|DefNew|Tenured|ParNew|CMS):"
    r"\s+(?P<before>\d+)K(?:\(\d+K\))?->(?P<after>\d+)K\((?P<total>\d+)K\)"
)
UNIFIED_METASPACE_RE: re.Pattern[str] = re.compile(
    r"^GC\((?P<gc_id>\d+)\)\s+Metaspace:\s+(?P<mb>\d+)K(?:\(\d+K\))?->(?P<ma>\d+)K\((?P<mt>\d+)K\)"
)
UNIFIED_TO_SPACE_RE: re.Pattern[str] = re.compile(r"^GC\((?P<gc_id>\d+)\)\s+To-space exhausted")
UNIFIED_CPU_RE: re.Pattern[str] = re.compile(
    rf"^GC\((?P<gc_id>\d+)\)\s+User=(?P<user>{DEC})s Sys=(?P<sys>{DEC})s Real=(?P<real>{DEC})s"
)
YOUNG_GENERATIONS: frozenset[str] = frozenset({"PSYoungGen", "DefNew", "ParNew"})


class UnifiedGCParser:
    """JDK 9+ unified logging for G1, Parallel, Serial and CMS.

    The "GC(n) Pause <Type> (tags) A->B(C) N ms" line is the event; gc,heap and gc,metaspace
    lines with the same GC id add young/old/metaspace sizes whether they come before or
    after it.
    """

    log_family: str = "unified"

    def __init__(self, gc_type_name: str = "G1 GC") -> None:
        self.gc_type_name = gc_type_name

    def parse(self, log_lines: list[str]) -> list[RawEvent]:
        """Parse unified pause lines and attach per-GC detail lines."""
        events: list[RawEvent] = []
        by_id: dict[int, RawEvent] = {}
        details: dict[int, dict[str, Any]] = {}  # detail lines seen before their pause line
        region_size_kb: int | None = None
        last_uptime: float | None = None

        for index, line in enumerate(log_lines):
            if not line.startswith("["):
                continue
            prefix = parse_unified_prefix(line.rstrip("\r\n"))
            if prefix is None:
                continue
            message = prefix.message
            # GC ids restart at 0 with every JVM run: details of a new run must not attach to
            # (or be taken from) the previous run's events.
            restarted = UNIFIED_COLLECTOR_LINE.search(message) is not None
            if prefix.uptime is not None:
                if (
                    last_uptime is not None
                    and prefix.uptime < last_uptime - _UPTIME_RESTART_TOLERANCE_SECONDS
                ):
                    restarted = True
                    region_size_kb = None
                last_uptime = prefix.uptime
            if restarted:
                by_id.clear()
                details.clear()
            if not message.startswith("GC("):
                if region_match := UNIFIED_REGION_SIZE_RE.search(message):
                    region_size_kb = parse_size_to_kb(
                        region_match.group("size") + region_match.group("unit")
                    )
                continue

            if (match := UNIFIED_PAUSE_RE.match(message)) and (
                match.group("ht") or match.group("type") in {"Remark", "Cleanup", "Initial Mark"}
            ):
                event = self._pause_event(match, prefix)
                event.update(line_index=index, line_end=index)
                gc_id = int(match.group("gc_id"))
                event["gc_id"] = gc_id
                event.update(details.pop(gc_id, {}))
                events.append(event)
                by_id[gc_id] = event
                continue

            update: dict[str, Any] = {}
            gc_id: int | None = None
            if m := UNIFIED_REGION_SIZE_RE.search(message):
                region_size_kb = parse_size_to_kb(m.group("size") + m.group("unit"))
            elif m := UNIFIED_REGION_COUNTS_RE.match(message):
                gc_id = int(m.group("gc_id"))
                name = m.group("region").lower()
                update[f"{name}_before_regions"] = int(m.group("before"))
                update[f"{name}_after_regions"] = int(m.group("after"))
                if m.group("total"):
                    update[f"{name}_total_regions"] = int(m.group("total"))
            elif m := UNIFIED_GENERATION_RE.match(message):
                gc_id = int(m.group("gc_id"))
                prefix_name = "young" if m.group("gen") in YOUNG_GENERATIONS else "old"
                update = {
                    f"{prefix_name}_before": int(m.group("before")),
                    f"{prefix_name}_after": int(m.group("after")),
                    f"{prefix_name}_total": int(m.group("total")),
                }
            elif m := UNIFIED_METASPACE_RE.match(message):
                gc_id = int(m.group("gc_id"))
                update = {
                    "metaspace_before": int(m.group("mb")),
                    "metaspace_after": int(m.group("ma")),
                    "metaspace_total": int(m.group("mt")),
                }
            elif m := UNIFIED_TO_SPACE_RE.match(message):
                gc_id = int(m.group("gc_id"))
                update = {"to_space_exhausted": True, "evacuation_failed": True}
            elif m := UNIFIED_CPU_RE.match(message):
                gc_id = int(m.group("gc_id"))
                if gc_id not in by_id:
                    continue  # CPU times follow their pause line; never hold them for a later one
                update = {
                    "cpu_user": to_float(m.group("user")),
                    "cpu_sys": to_float(m.group("sys")),
                    "cpu_real": to_float(m.group("real")),
                }

            if gc_id is None or not update:
                continue
            if update and "_regions" in next(iter(update)):
                update["region_size_kb"] = region_size_kb
            if gc_id in by_id:
                by_id[gc_id].update(update)
            else:
                details.setdefault(gc_id, {}).update(update)

        for event in events:
            apply_region_counts(event)
        return events

    def _pause_event(self, match: re.Match[str], prefix: UnifiedPrefix) -> RawEvent:
        pause_type = match.group("type")
        tags = paren_contents(match.group("tags"))
        failure = next((tag for tag in tags if tag.startswith("Evacuation Failure")), None)
        reason = failure.partition(":")[2].strip() if failure else ""
        cause_tags = [
            tag
            for tag in tags
            if tag not in G1_YOUNG_PHASE_TAGS and not tag.startswith("Evacuation Failure")
        ]
        cause = cause_tags[-1] if cause_tags else None
        if pause_type == "Mixed" or (pause_type == "Young" and "Mixed" in tags):
            kind = "Mixed"  # "Prepare Mixed" is a young-only pause and stays Young
        elif pause_type in ("Young", "Full", "Remark", "Cleanup"):
            kind = pause_type
        elif self.gc_type_name == "G1 GC":
            kind = "Young"  # JDK 9-11 G1 "Pause Initial Mark" piggybacks on a young pause
        else:
            kind = "Initial Mark"  # CMS
        if cause is None and kind in ("Remark", "Cleanup", "Initial Mark"):
            cause = f"{'G1' if self.gc_type_name == 'G1 GC' else 'CMS'} {kind}"
        return _new_event(
            timestamp=prefix.timestamp,
            uptime=prefix.uptime,
            gc_kind=kind,
            cause=cause,
            pause=to_float(match.group("pause")) / 1000,
            heap_before=parse_size_to_kb(match.group("hb")) if match.group("hb") else None,
            heap_after=parse_size_to_kb(match.group("ha")) if match.group("ha") else None,
            heap_total=parse_size_to_kb(match.group("ht")) if match.group("ht") else None,
            humongous_detected=cause is not None and "Humongous" in cause,
            evacuation_failed=failure is not None,
            evacuation_failure_reason=reason or None,
            to_space_exhausted="Allocation" in reason.split("/"),
            # JDK 9-11 "Pause Initial Mark" and JDK 12+ "(Concurrent Start)" start G1 marking
            concurrent_start=self.gc_type_name == "G1 GC"
            and (pause_type == "Initial Mark" or "Concurrent Start" in tags),
            stamp_at_pause_end=True,  # the pause line is written when the pause finishes
        )


def apply_region_counts(event: RawEvent) -> None:
    """Turn G1 region counts into young/old sizes (old includes humongous and archive)."""
    region_kb = event.get("region_size_kb")
    if not region_kb:
        return

    def regions(name: str, when: str) -> int | None:
        value = event.get(f"{name}_{when}_regions")
        return int(value) if value is not None else None

    for when in ("before", "after"):
        eden, survivor = regions("eden", when), regions("survivor", when)
        if eden is not None and survivor is not None:
            event[f"young_{when}"] = (eden + survivor) * region_kb
        old = regions("old", when)
        humongous = regions("humongous", when)
        if humongous is not None:
            event[f"humongous_{when}"] = humongous * region_kb
        if old is not None:
            extra = (humongous or 0) + (regions("archive", when) or 0)
            event[f"old_{when}"] = (old + extra) * region_kb
    old_before, old_after = regions("old", "before"), regions("old", "after")
    if old_before is not None and old_after is not None:
        # "Old regions" alone: humongous regions freed in the same pause would otherwise
        # cancel what the pause promoted
        event["promoted"] = max(0, old_after - old_before) * region_kb
    if "old_after" in event and event.get("heap_total"):
        # G1 has no fixed old-gen size; the committed heap is the capacity old can grow into
        event["old_total"] = event["heap_total"]


# ============================================================
# NON-PAUSE RECORDS: concurrent work and safepoints
# ============================================================

# JDK 11: "GC(1) Concurrent Cycle 250.000ms"; JDK 17+: "GC(4) Concurrent Mark Cycle 80.1ms"
UNIFIED_CONCURRENT_CYCLE_RE: re.Pattern[str] = re.compile(
    rf"\bGC\(\d+\) Concurrent (?:Mark |Undo )?Cycle (?P<ms>{DEC})ms\s*$"
)
# Unified CMS: "GC(1) Concurrent Mark 450.000ms", "GC(1) Concurrent Sweep 300.000ms". (G1's
# "Concurrent Mark (1.2s, 1.3s) 111ms" carries a parenthesis and is covered by its Cycle line.)
UNIFIED_CMS_CONCURRENT_RE: re.Pattern[str] = re.compile(
    rf"\bGC\(\d+\) Concurrent (?P<phase>Mark|Sweep) (?P<ms>{DEC})ms\s*$"
)
LEGACY_G1_CONCURRENT_MARK_RE: re.Pattern[str] = re.compile(
    rf"\[GC concurrent-mark-end, (?P<seconds>{DEC}) secs\]"
)
# "[CMS-concurrent-mark: 0.100/0.200 secs]": CPU time / elapsed time
LEGACY_CMS_CONCURRENT_RE: re.Pattern[str] = re.compile(
    rf"\[CMS-concurrent-(?P<phase>mark|sweep): {DEC}/(?P<seconds>{DEC}) secs\]"
)
# -XX:+PrintGCApplicationStoppedTime (Java 8) and -Xlog:safepoint (JDK 9-12)
STOPPED_TIME_RE: re.Pattern[str] = re.compile(
    rf"Total time for which application threads were stopped: (?P<stopped>{DEC}) seconds"
    rf"(?:, Stopping threads took: (?P<stopping>{DEC}) seconds)?"
)
# -Xlog:safepoint on JDK 13+ (runtime/safepoint.cpp, SafepointTracing::end). Fields between
# "Reaching safepoint" and "Total" differ by release (Cleanup, At safepoint, Leaving
# safepoint), and newer releases append a thread count:
#   Safepoint "G1CollectForAllocation", Time since last: 1 ns, Reaching safepoint: 2 ns,
#   Cleanup: 3 ns, At safepoint: 4 ns, Total: 9 ns
AT_SAFEPOINT_RE = re.compile(r"\bAt safepoint: (\d+) ns")
SAFEPOINT_RE: re.Pattern[str] = re.compile(
    r'Safepoint "(?P<operation>[^"]+)", Time since last: \d+ ns, '
    r"Reaching safepoint: (?P<reaching>\d+) ns, .*?\bTotal: (?P<total>\d+) ns"
)
# G1 at debug level: "GC(12) MMU target violated: 201.0ms (200.0ms/201.0ms)"
MMU_VIOLATED_RE: re.Pattern[str] = re.compile(rf"MMU target violated: (?P<ms>{DEC})ms")


def log_line_times(line: str) -> tuple[str | None, float | None]:
    """(datestamp, uptime seconds) of a log line of either family."""
    if line.startswith("["):
        return parse_unified_prefix_times(line)
    timestamp, uptime, _ = _legacy_stamp(line)
    return timestamp, uptime


def _side_record(kind: str, index: int, line: str, seconds: float, **fields: Any) -> SideRecord:
    timestamp, uptime = log_line_times(line)
    when = timestamp or (f"uptime {uptime:.3f}s" if uptime is not None else "")
    parsed: datetime | None = None
    if timestamp:
        try:
            parsed = parse_log_timestamp(timestamp)
        except ValueError:
            parsed = None
    return SideRecord(
        kind=kind,  # pyright: ignore[reportArgumentType] - callers pass the three literals
        line_number=index + 1,
        seconds=seconds,
        when=when,
        uptime_seconds=uptime,
        timestamp=parsed,
        **fields,
    )


def scan_side_records(log_lines: list[str]) -> list[SideRecord]:
    """Concurrent-work durations, safepoints and G1 pause-goal misses, in line order."""
    records: list[SideRecord] = []
    for index, line in enumerate(log_lines):
        if "oncurrent" in line:
            phase = "cycle"
            if match := UNIFIED_CONCURRENT_CYCLE_RE.search(line):
                seconds, label = to_float(match.group("ms")) / 1000, "G1 concurrent cycles"
            elif match := UNIFIED_CMS_CONCURRENT_RE.search(line):
                seconds = to_float(match.group("ms")) / 1000
                label, phase = "CMS concurrent mark and sweep phases", match.group("phase").lower()
            elif match := LEGACY_G1_CONCURRENT_MARK_RE.search(line):
                seconds, label = to_float(match.group("seconds")), "G1 concurrent marking phases"
                phase = "mark"
            elif match := LEGACY_CMS_CONCURRENT_RE.search(line):
                seconds = to_float(match.group("seconds"))
                label, phase = "CMS concurrent mark and sweep phases", match.group("phase")
            else:
                continue
            records.append(
                _side_record("concurrent", index, line, seconds, label=label, phase=phase)
            )
        elif "application threads were stopped" in line and (match := STOPPED_TIME_RE.search(line)):
            stopping = match.group("stopping")
            records.append(
                _side_record(
                    "safepoint",
                    index,
                    line,
                    to_float(match.group("stopped")),
                    stopping_seconds=to_float(stopping) if stopping else None,
                )
            )
        elif 'Safepoint "' in line and (match := SAFEPOINT_RE.search(line)):
            at_safepoint = AT_SAFEPOINT_RE.search(line)
            records.append(
                _side_record(
                    "safepoint",
                    index,
                    line,
                    int(match.group("total")) / 1e9,
                    stopping_seconds=int(match.group("reaching")) / 1e9,
                    at_safepoint_seconds=int(at_safepoint[1]) / 1e9 if at_safepoint else None,
                    operation=match.group("operation"),
                )
            )
        elif "MMU target violated" in line and (match := MMU_VIOLATED_RE.search(line)):
            records.append(_side_record("mmu", index, line, to_float(match.group("ms")) / 1000))
    return records


# ============================================================
# DETECTION
# ============================================================

UNIFIED_COLLECTOR_LINE: re.Pattern[str] = re.compile(
    r"\bUsing (?P<name>G1|Parallel|Serial|Concurrent Mark Sweep|The Z Garbage Collector"
    r"|Shenandoah|Epsilon)\b"
)
UNIFIED_SUPPORTED_COLLECTORS: dict[str, str] = {
    "G1": "G1 GC",
    "Parallel": "Parallel GC",
    "Serial": "Serial GC",
    "Concurrent Mark Sweep": "CMS GC",
}
UNIFIED_UNSUPPORTED_COLLECTORS: dict[str, str] = {
    "The Z Garbage Collector": "ZGC",
    "Shenandoah": "Shenandoah",
    "Epsilon": "Epsilon",
}
SUPPORTED_FORMATS_TEXT = (
    "Supported: G1, Parallel, CMS and Serial, in Java 8 (-XX:+PrintGC/-XX:+PrintGCDetails) "
    "and unified (-Xlog:gc*) formats"
)
# Java 8 "CommandLine flags:" collector switches, most specific first
LEGACY_FLAG_COLLECTORS: tuple[tuple[str, str], ...] = (
    ("-XX:+UseG1GC", "G1 GC"),
    ("-XX:+UseConcMarkSweepGC", "CMS GC"),
    ("-XX:+UseParallelOldGC", "Parallel GC"),
    ("-XX:+UseParallelGC", "Parallel GC"),
    ("-XX:+UseParNewGC", "ParNew GC"),
    ("-XX:+UseSerialGC", "Serial GC"),
)


def is_unified_line(line: str) -> bool:
    """True for a unified-logging line with a gc tag set."""
    return line.startswith("[") and parse_unified_prefix(line.rstrip("\r\n")) is not None


def _unsupported(name: str, detail: str = "") -> ValueError:
    return ValueError(f"{name} logs are not supported{detail}. {SUPPORTED_FORMATS_TEXT}")


def _detect_unified_parser(sample_lines: list[str]) -> GCParser:
    for line in sample_lines:
        if "Using " in line and (match := UNIFIED_COLLECTOR_LINE.search(line)):
            name = match.group("name")
            if name in UNIFIED_UNSUPPORTED_COLLECTORS:
                raise _unsupported(UNIFIED_UNSUPPORTED_COLLECTORS[name], f' (found "Using {name}")')
            return UnifiedGCParser(UNIFIED_SUPPORTED_COLLECTORS[name])

    # No "Using ..." header (e.g. a rotated file): infer from content
    sample = "".join(sample_lines)
    if "PSYoungGen" in sample or "ParOldGen" in sample:
        return UnifiedGCParser("Parallel GC")
    if "DefNew" in sample or "Tenured" in sample:
        return UnifiedGCParser("Serial GC")
    if "ParNew" in sample or "CMS" in sample:
        return UnifiedGCParser("CMS GC")
    if "Pause Mark Start" in sample or "Garbage Collection (" in sample:
        raise _unsupported("ZGC")
    if "Pause Init Mark" in sample or "Pause Final Mark" in sample:
        raise _unsupported("Shenandoah")
    return UnifiedGCParser("G1 GC")  # G1 is the JDK 9+ default collector


def _legacy_parser(name: str) -> GCParser:
    if name == "G1 GC":
        return G1LegacyGCParser()
    if name == "Parallel GC":
        return ParallelGCParser()
    return GenerationalGCParser(name)


def detect_gc_type_and_create_parser(log_lines: list[str]) -> GCParser:
    """Detect log format family (unified vs. legacy), then the collector."""
    sample_lines = log_lines[:400]
    if any(is_unified_line(line) for line in sample_lines):
        return _detect_unified_parser(sample_lines)

    for line in sample_lines:
        if line.startswith("CommandLine flags:"):
            for flag, name in LEGACY_FLAG_COLLECTORS:
                if flag in line:
                    return _legacy_parser(name)

    sample = "".join(sample_lines)
    if "PSYoungGen" in sample or "ParOldGen" in sample:
        return ParallelGCParser()
    if any(p in sample for p in ("[GC pause", "G1 Evacuation", "[GC remark", "G1Ergonomics")):
        return G1LegacyGCParser()
    if any(p in sample for p in ("CMS-initial-mark", "CMS-remark", "[CMS", "CMS-concurrent")):
        return GenerationalGCParser("CMS GC")
    if "ParNew" in sample:
        return GenerationalGCParser("ParNew GC")
    if "DefNew" in sample or "Tenured" in sample:
        return GenerationalGCParser("Serial GC")
    if any(LEGACY_HEAP_ONLY_RE.match(_legacy_stamp(line)[2]) for line in sample_lines):
        # -XX:+PrintGC only: collector unknown, heap transitions still parse
        return GenerationalGCParser("Unknown collector (-XX:+PrintGC only)")
    raise ValueError(f"Unsupported or unrecognized GC log format. {SUPPORTED_FORMATS_TEXT}")


def validate_old_gen_values(
    heap_before: int,
    heap_after: int,
    heap_total: int,
    young_before: int,
    young_after: int,
    young_total: int,
) -> tuple[int, int, int]:
    """Old gen = heap - young, clamped at 0 for corrupted log data."""
    old_before = max(0, heap_before - young_before)
    old_after = max(0, heap_after - young_after)
    old_total = max(0, heap_total - young_total)
    return old_before, old_after, old_total
