"""Collector-specific GC log parsers and format/collector detection.

Every parser turns log lines into ``PauseRecord`` objects (models.py) that
``events.normalize_event`` turns into ``GCEvent``.

Two log families exist:

* Legacy (Java 8 and earlier, ``-XX:+PrintGCDetails``): one record per collection, sometimes
  spread over several physical lines (tenuring tables, interleaved concurrent phases,
  ``PrintAdaptiveSizePolicy``). ``iter_legacy_records`` joins and cleans those first.
* Unified (JDK 9+, ``-Xlog:gc*``): one ``Pause ...`` line per collection with detail lines
  linked by ``GC(n)``; the pause-line layout is shared by all collectors.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from datetime import UTC, datetime
from typing import Literal, Protocol

from .events import parse_log_timestamp, parse_size_to_kb
from .jvm_runs import RestartDetector
from .models import GCKind, PauseRecord, SideRecord
from .reader import LineSource, LineWindow, as_window

type LegacyRecordKind = Literal["Young", "Full"]


class GCParser(Protocol):
    """Protocol defining GC parser interface."""

    gc_type_name: str
    log_family: str  # "legacy" or "unified"

    def parse(self, log_lines: LineSource) -> list[PauseRecord]:
        """Parse log lines (a list, any iterable, or a shared ``LineWindow``)."""
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


def _young_or_full(match: re.Match[str]) -> LegacyRecordKind:
    return "Full" if match.group("full") == "Full GC" else "Young"


def _metaspace(event: PauseRecord, match: re.Match[str] | None) -> None:
    if match is not None and match.group("mb") is not None:
        event.metaspace_before = int(match.group("mb"))
        event.metaspace_after = int(match.group("ma"))


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


def legacy_survivor_after_gc(log_lines: LineSource, end: int) -> tuple[int, float] | None:
    """Survivor ("from space") capacity (KB) and occupancy (%) after the record ending on
    line ``end``.

    Only read from the "Heap after GC" block that directly follows the record.
    """
    in_block = False
    for line in as_window(log_lines).range(end + 1, end + 1 + MAX_HEAP_AFTER_GC_LINES):
        if not in_block:
            if line.startswith(_HEAP_AFTER_GC):
                in_block = True
            elif line.strip() and not line[:1].isspace():
                break  # another record or block came first
            continue
        if line.startswith("}"):
            break
        if match := _FROM_SPACE_RE.match(line):
            return int(match.group("capacity")), float(match.group("used"))
    return None


def legacy_cpu_times(
    log_lines: LineSource, start: int, end: int
) -> tuple[float, float, float] | None:
    """user/sys/real of the record on lines ``start``..``end`` (0-based), if it logs them.

    The figure normally closes the record's own line. Java 8 G1 with PrintGCDetails prints it
    on an indented line after the detail lines, so indented lines after ``end`` are searched
    too.
    """
    found: re.Match[str] | None = None
    window = as_window(log_lines)
    for index in range(start, end + 1 + MAX_TIMES_LOOKAHEAD_LINES):
        line = window.get(index)
        if line is None:
            break
        if index > end and not line[:1].isspace():
            break
        matches = list(LEGACY_TIMES_RE.finditer(_CONCURRENT_WITH_TIMES.sub("", line)))
        if matches:
            found = matches[-1]
            if index > end:
                break
    if found is None:
        return None
    return (
        to_float(found.group("user")),
        to_float(found.group("sys")),
        to_float(found.group("real")),
    )


def _apply_legacy_details(event: PauseRecord, window: LineWindow, start: int, end: int) -> None:
    """Line range, [Times: ...] and the survivor block that follow a legacy record."""
    event.line_index, event.line_end = start, end
    if cpu := legacy_cpu_times(window, start, end):
        event.cpu_user, event.cpu_sys, event.cpu_real = cpu


def clean_legacy_record(text: str) -> str:
    """Strip interleaved non-pause fragments from a joined legacy record."""
    for pattern in LEGACY_NOISE:
        text = pattern.sub("", text)
    return text.replace("\n", "")


# A record that begins after text another thread had not finished writing (stdout shared
# with the application, e.g. Tomcat's catalina.out):
#   "...Reloading Context [/app] has started 225462026-11-18T03:07:40.987+0000: 0.077: [GC (..."
# Only a record start with a datestamp counts: the date's fixed shape (a four-digit year and
# "-") shows where it begins. An uptime alone cannot be told apart from digits the other
# thread wrote ("started 44177" + "0.110:" reads as "441770.110:"), so such a record is left
# unparsed and reported, never given a guessed time. Sub-phases inside records ("[GC
# ref-proc", "[GC concurrent-...") never match.
_RECORD_OPENER = r"\[(?:(?:Full GC|GC)(?: pause)? \(|GC (?:remark|cleanup)\b)"
_EMBEDDED_RECORD_START: re.Pattern[str] = re.compile(
    rf"{LEGACY_DATE}:\s+(?:\d+[.,]\d+:\s+)?{_RECORD_OPENER}"
)


# A GC stamp at the start of a line whose record opener comes later: another thread's text
# was written between the stamp and "[GC (...": "1.462: 17-Nov-2026 ... started 11[GC (..."
_STAMP_FIRST: re.Pattern[str] = re.compile(
    rf"^(?:{LEGACY_DATE}:\s+(?:\d+[.,]\d+:\s+)?|\d+[.,]\d+:\s+)(?!\[)"
)
_RECORD_OPENER_RE: re.Pattern[str] = re.compile(_RECORD_OPENER)


def legacy_record_offset(line: str) -> int | None:
    """Where a legacy GC record starts on ``line``: 0, a later position when the record was
    written after unfinished text from another thread, or None when none starts here."""
    if LEGACY_RECORD_START.match(line):
        return 0
    if line[:1].isspace() or ("[GC" not in line and "[Full GC" not in line):
        return None
    if match := _EMBEDDED_RECORD_START.search(line):
        return match.start()
    if _STAMP_FIRST.match(line) and _RECORD_OPENER_RE.search(line):
        return 0  # the inserted text is removed when the record is parsed
    return None


def read_legacy_record(window: LineWindow, start: int, offset: int = 0) -> tuple[int, str]:
    """(last line index, cleaned text) of the legacy record that starts on line ``start``
    (``offset`` characters in).

    A record whose brackets are unbalanced at the end of its first line continues on the
    following lines until they balance (or a new record starts).
    """
    line = window[start].rstrip("\r\n")[offset:]
    parts = [line]
    depth = line.count("[") - line.count("]")
    index = start
    while depth > 0 and index - start < MAX_CONTINUATION_LINES:
        following = window.get(index + 1)
        if following is None:
            break
        nxt = following.rstrip("\r\n")
        if LEGACY_RECORD_START.match(nxt):
            break
        index += 1
        parts.append(nxt)
        depth += nxt.count("[") - nxt.count("]")
    return index, clean_legacy_record("\n".join(parts))


def iter_legacy_records(log_lines: LineSource) -> Iterator[tuple[int, int, str]]:
    """Yield (first_line_index, last_line_index, cleaned_text) for each legacy GC record."""
    window = as_window(log_lines)
    index = 0
    while (line := window.get(index)) is not None:
        offset = legacy_record_offset(line.rstrip("\r\n"))
        if offset is None:
            index += 1
            continue
        end, text = read_legacy_record(window, index, offset)
        yield index, end, text
        index = end + 1


# Shapes a physical line can take when it continues a legacy GC record: an indented detail,
# a fragment that resumes the record (": 272640K->...", ", 0.015 secs]", " (concurrent mode
# failure)"), an inner GC stamp, a tenuring table line, or a bracketed GC section.
LEGACY_CONTINUATION_RE: re.Pattern[str] = re.compile(
    rf"^(?:\s|[:,\]\(]|{LEGACY_DATE}:|\d+[.,]\d+:\s|\d+K->|Desired survivor size |- age +\d+:"
    r"|\[(?:PSYoungGen|ParOldGen|PSOldGen|PSPermGen|ParNew|DefNew|Tenured|CMS|1 CMS-|Times"
    r"|Metaspace|Perm|GC|Full GC|YG occupancy|Rescan|weak refs processing|class unloading"
    r"|scrub|Soft|Weak|Final|Phantom|JNI Weak|G1Ergonomics|Eden))"
)


def legacy_record_without_foreign_lines(
    log_lines: LineSource, start: int, end: int, offset: int = 0
) -> str | None:
    """The record on lines ``start``..``end`` rebuilt without lines that cannot belong to it.

    Tomcat writes JVM stdout, and with it Java 8 GC output, to catalina.out; an application
    line can land inside a multi-line GC record. Returns None when every continuation line
    has a GC shape (nothing to remove). Parsers use this only for records that fail to parse.
    """
    window = as_window(log_lines)
    kept = [window[start].rstrip("\r\n")[offset:]]
    removed_any = False
    for line in window.range(start + 1, end + 1):
        text = line.rstrip("\r\n")
        if not text.strip():
            continue
        if LEGACY_CONTINUATION_RE.match(text):
            kept.append(text)
        else:
            removed_any = True
    return clean_legacy_record("\n".join(kept)) if removed_any else None


# Where GC text resumes after text another thread wrote into the middle of a record: a
# bracketed GC section, or an inner GC stamp
_GC_TEXT_RESUMES: re.Pattern[str] = re.compile(
    r"\[(?:PSYoungGen|ParOldGen|PSOldGen|PSPermGen|ParNew|DefNew|Tenured|CMS|1 CMS-|Times"
    r"|Metaspace|Perm|YG occupancy|Rescan|Eden|GC ref-proc|Finalize Marking|Unloading)\b"
    rf"|{_RECORD_OPENER}|{LEGACY_DATE}:\s|(?<![\d.,])\d+[.,]\d+:\s+\["
)
_INSERTION_STARTS_AFTER = frozenset(" )],")
MAX_INSERTION_CANDIDATES = 4000


def legacy_record_without_inserted_text(text: str, parses: Callable[[str], bool]) -> str | None:
    """``text`` with the smallest span removed that makes it parse, or None.

    On shared stdout another thread's text can land inside a GC record on the same line:
    "[GC (Allocation Failure) 17-Nov-2026 ... has started 44177[PSYoungGen: ...". The
    inserted text ends where GC text resumes and starts at a token boundary; the smallest
    removal that leaves a complete record is the insertion (a larger one would drop GC
    text). Used only for records that fail to parse as written.
    """
    resumes = [match.start() for match in _GC_TEXT_RESUMES.finditer(text)]
    cuts = sorted(
        (end - start, start, end)
        for end in resumes
        for start in range(1, end)
        if text[start - 1] in _INSERTION_STARTS_AFTER
    )
    for _, start, end in cuts[:MAX_INSERTION_CANDIDATES]:
        candidate = text[:start] + text[end:]
        if parses(candidate):
            return candidate
    return None


def repair_legacy_record(
    text: str, window: LineWindow, start: int, end: int, parses: Callable[[str], bool]
) -> str | None:
    """A version of a record that failed to parse with another thread's output removed:
    whole foreign lines first, then text inserted within a line."""
    offset = legacy_record_offset(window[start].rstrip("\r\n")) or 0
    without_lines = legacy_record_without_foreign_lines(window, start, end, offset)
    if without_lines is not None and parses(without_lines):
        return without_lines
    return legacy_record_without_inserted_text(without_lines or text, parses)


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

    def parse(self, log_lines: LineSource) -> list[PauseRecord]:
        """Parse every legacy record."""
        window = as_window(log_lines)
        events: list[PauseRecord] = []
        for start, end, text in iter_legacy_records(window):
            timestamp, uptime, rest = _legacy_stamp(text)
            event = self._parse_record(rest)
            if event is None and (
                rebuilt := repair_legacy_record(
                    text,
                    window,
                    start,
                    end,
                    lambda candidate: self._parse_record(_legacy_stamp(candidate)[2]) is not None,
                )
            ):
                timestamp, uptime, rest = _legacy_stamp(rebuilt)
                event = self._parse_record(rest)
            if event is None:
                continue
            event.timestamp, event.uptime = timestamp, uptime
            _apply_legacy_details(event, window, start, end)
            if survivor := legacy_survivor_after_gc(window, end):
                event.survivor_capacity, event.survivor_used_pct = survivor
            events.append(event)
        return events

    def _parse_record(self, rest: str) -> PauseRecord | None:
        raise NotImplementedError

    @staticmethod
    def _heap_only(rest: str) -> PauseRecord | None:
        match = LEGACY_HEAP_ONLY_RE.match(rest)
        if match is None:
            return None
        event = PauseRecord(
            gc_kind=_young_or_full(match),
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

    def _parse_record(self, rest: str) -> PauseRecord | None:
        match = self.RECORD_RE.match(rest)
        if match is None:
            return self._heap_only(rest)
        young = (int(match.group("yb")), int(match.group("ya")), int(match.group("yt")))
        heap = (int(match.group("hb")), int(match.group("ha")), int(match.group("ht")))
        old: tuple[int | None, int | None, int | None]
        if match.group("ob") is not None:
            old = (int(match.group("ob")), int(match.group("oa")), int(match.group("ot")))
        else:
            old = old_gen_from_heap_and_young(heap, young)
        event = PauseRecord(
            gc_kind=_young_or_full(match),
            cause=match.group("cause"),
            pause=to_float(match.group("pause")),
            heap_before=heap[0],
            heap_after=heap[1],
            heap_total=heap[2],
            young_before=young[0],
            young_after=young[1],
            old_before=old[0],
            old_after=old[1],
            old_total=old[2],
            # "[GC (Allocation Failure) --[PSYoungGen:" marks a promotion failure
            promotion_failed=match.group("promo") is not None,
        )
        if None in old:
            event.note_inconsistency(YOUNG_ABOVE_HEAP)
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

    def _parse_record(self, rest: str) -> PauseRecord | None:
        phases: tuple[tuple[GCKind, re.Pattern[str]], ...] = (
            ("Initial Mark", self.INITIAL_MARK_RE),
            ("Remark", self.REMARK_RE),
        )
        for kind, pattern in phases:
            if match := pattern.match(rest):
                heap_after, heap_total = int(match.group("ha")), int(match.group("ht"))
                old_after, old_total = int(match.group("oa")), int(match.group("ot"))
                return PauseRecord(
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
        event = PauseRecord(
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
            event.young_before, event.young_after = young[0], young[1]
        if has_old:
            event.old_before = int(match.group("ob"))
            event.old_after = int(match.group("oa"))
            event.old_total = int(match.group("ot"))
            if young is not None:
                event.young_after = young_after_full_collection(heap, young, event.old_after)
        elif young is not None:
            event.old_before, event.old_after, event.old_total = old_gen_from_heap_and_young(
                heap, young
            )
            if event.old_before is None or event.old_after is None or event.old_total is None:
                event.note_inconsistency(YOUNG_ABOVE_HEAP)
        _metaspace(event, match)
        return event


# ---------------------------------------------------------------- G1 (Java 8)


# Java 8 G1 prints Eden, Survivors and Heap rounded to 0.1 MB: three roundings of up to
# 0.05 MB each. A shortfall within 1 MB is rounding; a larger one is an inconsistent record.
G1_LEGACY_ROUNDING_KB = 1024


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

    def parse(self, log_lines: LineSource) -> list[PauseRecord]:
        """Parse Java 8 G1 records, attaching detail lines to the preceding pause."""
        window = as_window(log_lines)
        events: list[PauseRecord] = []
        pending: PauseRecord | None = None  # header seen, waiting for its detail line
        record_end = -1  # last line of the latest record; its continuation lines follow

        for index, line in enumerate(window):
            offset = legacy_record_offset(line.rstrip("\r\n")) if index > record_end else None
            if offset is not None:
                end, text = read_legacy_record(window, index, offset)
                record_end = end
                event = self._parse_record(text)
                if event is None and (
                    rebuilt := repair_legacy_record(
                        text,
                        window,
                        index,
                        end,
                        lambda candidate: self._parse_record(candidate) is not None,
                    )
                ):
                    event = self._parse_record(rebuilt)
                if event is not None:
                    _apply_legacy_details(event, window, index, end)
                    events.append(event)
                    pending = event
                continue
            if pending is not None and "[Eden:" in line and (detail := self.DETAIL_RE.search(line)):
                self._apply_detail(pending, detail)
                pending = None
            elif pending is not None and "Evacuation Failure" in line:
                pending.evacuation_failed = True  # "      [Evacuation Failure: 5.4 ms]"
        return events

    def _parse_record(self, text: str) -> PauseRecord | None:
        timestamp, uptime, rest = _legacy_stamp(text)
        if match := self.PAUSE_RE.match(rest):
            tags = paren_contents(match.group("tags"))
            cause = tags[0] if tags else None
            to_space = any(tag.startswith("to-space") for tag in tags)
            event = PauseRecord(
                timestamp=timestamp,
                uptime=uptime,
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
            event = PauseRecord(
                timestamp=timestamp,
                uptime=uptime,
                gc_kind="Full",
                cause=match.group("cause"),
                pause=to_float(match.group("pause")),
            )
            self._apply_heap(event, match)
            return event
        if match := self.REMARK_RE.match(rest):
            return PauseRecord(
                timestamp=timestamp,
                uptime=uptime,
                gc_kind="Remark",
                cause="G1 Remark",
                pause=to_float(match.group("pause")),
            )
        if match := self.CLEANUP_RE.match(rest):
            event = PauseRecord(
                timestamp=timestamp,
                uptime=uptime,
                gc_kind="Cleanup",
                cause="G1 Cleanup",
                pause=to_float(match.group("pause")),
            )
            self._apply_heap(event, match)
            return event
        return None

    @staticmethod
    def _apply_heap(event: PauseRecord, match: re.Match[str]) -> tuple[int, int, int]:
        event.heap_before = parse_size_to_kb(match.group("hb"))
        event.heap_after = parse_size_to_kb(match.group("ha"))
        event.heap_total = parse_size_to_kb(match.group("ht"))
        return event.heap_before, event.heap_after, event.heap_total

    def _apply_detail(self, event: PauseRecord, match: re.Match[str]) -> None:
        heap_before, heap_after, _ = self._apply_heap(event, match)
        young_before = parse_size_to_kb(match.group("eb")) + parse_size_to_kb(match.group("sb"))
        young_after = parse_size_to_kb(match.group("ea")) + parse_size_to_kb(match.group("sa"))
        event.young_before, event.young_after = young_before, young_after
        event.old_before = self._old_from_rounded(event, heap_before - young_before)
        event.old_after = self._old_from_rounded(event, heap_after - young_after)
        _metaspace(event, match)

    @staticmethod
    def _old_from_rounded(event: PauseRecord, old_kb: int) -> int | None:
        """heap - young from sizes printed to 0.1 MB: a small shortfall is rounding."""
        if old_kb >= -G1_LEGACY_ROUNDING_KB:
            return max(0, old_kb)
        event.note_inconsistency(YOUNG_ABOVE_HEAP)
        return None


# ============================================================
# UNIFIED LOGGING (JDK 9+)
# ============================================================

UNIFIED_LEVELS: frozenset[str] = frozenset({"trace", "debug", "info", "warning", "error"})
_DECORATOR_RE = re.compile(r"\[([^\]]*)\]")
_NUMBER_DECORATOR_RE = re.compile(r"^\d+$")
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


class UnifiedPrefix:
    """Decorators of a unified-logging line."""

    __slots__ = ("level", "message", "pid", "tags", "timestamp", "uptime")

    def __init__(
        self,
        timestamp: str | None,
        uptime: float | None,
        level: str | None,
        tags: str,
        message: str,
        pid: int | None = None,
    ) -> None:
        self.timestamp = timestamp
        self.uptime = uptime
        self.level = level
        self.tags = tags
        self.message = message
        self.pid = pid


def _time_decorator(value: str) -> tuple[str | None, float | None] | None:
    """(datestamp, uptime seconds) when ``value`` is a time decorator, else None.

    time/utctime (ISO), uptime ("10.000s"), timemillis/uptimemillis ("123ms") and
    timenanos/uptimenanos ("123ns"); epoch values are told from uptimes by size.
    """
    if _ISO_DECORATOR_RE.match(value):
        return value, None
    if m := _UPTIME_S_RE.match(value):
        return None, float(m.group(1).replace(",", "."))
    if m := _MS_RE.match(value):
        number = int(m.group(1))
        if number >= _EPOCH_MS_FLOOR:
            return datetime.fromtimestamp(number / 1000, tz=UTC).isoformat(), None
        return None, number / 1000
    if m := _NS_RE.match(value):
        number = int(m.group(1))
        if number >= _EPOCH_MS_FLOOR * 10**6:
            return datetime.fromtimestamp(number / 1e9, tz=UTC).isoformat(), None
        return None, number / 1e9
    return None


def parse_unified_prefix(line: str) -> UnifiedPrefix | None:
    """Split "[decorator]...[level][gc,tags] message" into its parts.

    Handles any decorator set: time/utctime (ISO), uptime ("10.000s"), uptimemillis /
    timemillis ("123ms"), uptimenanos/timenanos ("123ns"), pid/tid, level (padded or not).
    Decorators are always written pid before tid, so with two bare numbers the first is the
    pid; a single bare number could be either and is not taken as the pid.
    The level and tags decorators are optional: a line with a time decorator and a GC message
    ("GC(n) ...", "Using G1", heap sizing) is accepted without them.
    Returns None for lines that are not GC unified log lines.
    """
    position = 0
    timestamp: str | None = None
    uptime: float | None = None
    level: str | None = None
    tags: str | None = None
    numbers: list[int] = []
    while position < len(line) and line[position] == "[":
        match = _DECORATOR_RE.match(line, position)
        if match is None:
            break
        value = match.group(1).strip()
        position = match.end()
        if _NUMBER_DECORATOR_RE.match(value):
            numbers.append(int(value))
        elif (times := _time_decorator(value)) is not None:
            timestamp = times[0] or timestamp
            uptime = times[1] if times[1] is not None else uptime
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
    pid = numbers[0] if len(numbers) >= 2 else None
    return UnifiedPrefix(timestamp, uptime, level, tags, message, pid)


def parse_unified_prefix_times(line: str) -> tuple[str | None, float | None]:
    """(datestamp, uptime seconds) from the leading decorators of any unified line.

    Reads the same time decorators as ``parse_unified_prefix``; they are always written
    first, so reading stops at the first decorator that is not a time.
    """
    timestamp: str | None = None
    uptime: float | None = None
    position = 0
    while position < len(line) and line[position] == "[":
        match = _DECORATOR_RE.match(line, position)
        if match is None:
            break
        times = _time_decorator(match.group(1).strip())
        if times is None:
            break
        timestamp = times[0] or timestamp
        uptime = times[1] if times[1] is not None else uptime
        position = match.end()
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

    def parse(self, log_lines: LineSource) -> list[PauseRecord]:
        """Parse unified pause lines and attach per-GC detail lines."""
        events: list[PauseRecord] = []
        by_id: dict[int, PauseRecord] = {}
        pending: dict[int, list[DetailUpdate]] = {}  # detail lines before their pause line
        region_size_kb: int | None = None
        restarts = RestartDetector()

        for index, line in enumerate(log_lines):
            if not line.startswith("["):
                continue
            text = line.rstrip("\r\n")
            prefix = parse_unified_prefix(text)
            if prefix is None:
                continue
            message = prefix.message
            # GC ids restart at 0 with every JVM run: details of a new run must not attach to
            # (or be taken from) the previous run's events.
            if reason := restarts.restarted(text, prefix.uptime, prefix.pid):
                by_id.clear()
                pending.clear()
                if reason != "header":
                    region_size_kb = None
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
                event.line_index = event.line_end = index
                gc_id = int(match.group("gc_id"))
                event.gc_id = gc_id
                for apply in pending.pop(gc_id, []):
                    apply(event)
                events.append(event)
                by_id[gc_id] = event
                continue

            detail = unified_detail(message, region_size_kb)
            if detail is None:
                continue
            gc_id, apply, may_precede_pause = detail
            if gc_id in by_id:
                apply(by_id[gc_id])
            elif may_precede_pause:
                pending.setdefault(gc_id, []).append(apply)

        for event in events:
            apply_region_counts(event)
        return events

    def _pause_event(self, match: re.Match[str], prefix: UnifiedPrefix) -> PauseRecord:
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
        kind: GCKind
        if pause_type == "Mixed" or (pause_type == "Young" and "Mixed" in tags):
            kind = "Mixed"  # "Prepare Mixed" is a young-only pause and stays Young
        elif pause_type == "Young":
            kind = "Young"
        elif pause_type == "Full":
            kind = "Full"
        elif pause_type == "Remark":
            kind = "Remark"
        elif pause_type == "Cleanup":
            kind = "Cleanup"
        elif self.gc_type_name == "G1 GC":
            kind = "Young"  # JDK 9-11 G1 "Pause Initial Mark" piggybacks on a young pause
        else:
            kind = "Initial Mark"  # CMS
        if cause is None and kind in ("Remark", "Cleanup", "Initial Mark"):
            cause = f"{'G1' if self.gc_type_name == 'G1 GC' else 'CMS'} {kind}"
        return PauseRecord(
            timestamp=prefix.timestamp,
            uptime=prefix.uptime,
            pid=prefix.pid,
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


type DetailUpdate = Callable[[PauseRecord], None]


def unified_detail(
    message: str, region_size_kb: int | None
) -> tuple[int, DetailUpdate, bool] | None:
    """(GC id, how to apply it, whether it may precede its pause line) for a unified per-GC
    detail line, or None for other lines.

    Heap, region and metaspace lines are written before the pause line that carries the
    duration; CPU times always follow it, so one without its pause is never held for later.
    """
    if m := UNIFIED_REGION_COUNTS_RE.match(message):
        name = m.group("region").lower()
        before, after, total = int(m.group("before")), int(m.group("after")), m.group("total")

        def apply_regions(event: PauseRecord) -> None:
            event.region_counts[f"{name}_before"] = before
            event.region_counts[f"{name}_after"] = after
            if total:
                event.region_counts[f"{name}_total"] = int(total)
            event.region_size_kb = region_size_kb

        return int(m.group("gc_id")), apply_regions, True
    if m := UNIFIED_GENERATION_RE.match(message):
        young = m.group("gen") in YOUNG_GENERATIONS
        sizes = int(m.group("before")), int(m.group("after")), int(m.group("total"))

        def apply_generation(event: PauseRecord) -> None:
            if young:
                event.young_before, event.young_after = sizes[0], sizes[1]
            else:
                event.old_before, event.old_after, event.old_total = sizes

        return int(m.group("gc_id")), apply_generation, True
    if m := UNIFIED_METASPACE_RE.match(message):
        metaspace = int(m.group("mb")), int(m.group("ma"))

        def apply_metaspace(event: PauseRecord) -> None:
            event.metaspace_before, event.metaspace_after = metaspace

        return int(m.group("gc_id")), apply_metaspace, True
    if m := UNIFIED_TO_SPACE_RE.match(message):

        def apply_to_space(event: PauseRecord) -> None:
            event.to_space_exhausted = event.evacuation_failed = True

        return int(m.group("gc_id")), apply_to_space, True
    if m := UNIFIED_CPU_RE.match(message):
        cpu = to_float(m.group("user")), to_float(m.group("sys")), to_float(m.group("real"))

        def apply_cpu(event: PauseRecord) -> None:
            event.cpu_user, event.cpu_sys, event.cpu_real = cpu

        return int(m.group("gc_id")), apply_cpu, False
    return None


def apply_region_counts(event: PauseRecord) -> None:
    """Turn G1 region counts into young/old sizes (old includes humongous and archive)."""
    region_kb = event.region_size_kb
    if not region_kb:
        return
    counts = event.region_counts
    for when in ("before", "after"):
        eden, survivor = counts.get(f"eden_{when}"), counts.get(f"survivor_{when}")
        young = (eden + survivor) * region_kb if eden is not None and survivor is not None else None
        old = counts.get(f"old_{when}")
        humongous = counts.get(f"humongous_{when}")
        humongous_kb = humongous * region_kb if humongous is not None else None
        old_kb = None
        if old is not None:
            old_kb = (old + (humongous or 0) + counts.get(f"archive_{when}", 0)) * region_kb
        if when == "before":
            event.young_before = young if young is not None else event.young_before
            event.humongous_before = humongous_kb
            event.old_before = old_kb if old_kb is not None else event.old_before
        else:
            event.young_after = young if young is not None else event.young_after
            event.humongous_after = humongous_kb
            event.old_after = old_kb if old_kb is not None else event.old_after
    old_before, old_after = counts.get("old_before"), counts.get("old_after")
    if old_before is not None and old_after is not None:
        # "Old regions" alone: humongous regions freed in the same pause would otherwise
        # cancel what the pause promoted
        event.promoted = max(0, old_after - old_before) * region_kb
    if old_after is not None and event.heap_total:
        # G1 has no fixed old-gen size; the committed heap is the capacity old can grow into
        event.old_total = event.heap_total


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


type SideRecordKind = Literal["concurrent", "safepoint", "mmu"]


def _side_record(
    kind: SideRecordKind,
    index: int,
    line: str,
    seconds: float,
    *,
    label: str = "",
    phase: str = "",
    stopping_seconds: float | None = None,
    at_safepoint_seconds: float | None = None,
    operation: str = "",
) -> SideRecord:
    timestamp, uptime = log_line_times(line)
    when = timestamp or (f"uptime {uptime:.3f}s" if uptime is not None else "")
    parsed: datetime | None = None
    if timestamp:
        try:
            parsed = parse_log_timestamp(timestamp)
        except ValueError:
            parsed = None
    return SideRecord(
        kind=kind,
        line_number=index + 1,
        seconds=seconds,
        when=when,
        uptime_seconds=uptime,
        timestamp=parsed,
        label=label,
        phase=phase,
        stopping_seconds=stopping_seconds,
        at_safepoint_seconds=at_safepoint_seconds,
        operation=operation,
    )


def side_record_for(index: int, line: str) -> SideRecord | None:
    """Concurrent-work duration, safepoint or G1 pause-goal miss on line ``index``, if any."""
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
            return None
        return _side_record("concurrent", index, line, seconds, label=label, phase=phase)
    if "application threads were stopped" in line and (match := STOPPED_TIME_RE.search(line)):
        stopping = match.group("stopping")
        return _side_record(
            "safepoint",
            index,
            line,
            to_float(match.group("stopped")),
            stopping_seconds=to_float(stopping) if stopping else None,
        )
    if 'Safepoint "' in line and (match := SAFEPOINT_RE.search(line)):
        at_safepoint = AT_SAFEPOINT_RE.search(line)
        return _side_record(
            "safepoint",
            index,
            line,
            int(match.group("total")) / 1e9,
            stopping_seconds=int(match.group("reaching")) / 1e9,
            at_safepoint_seconds=int(at_safepoint[1]) / 1e9 if at_safepoint else None,
            operation=match.group("operation"),
        )
    if "MMU target violated" in line and (match := MMU_VIOLATED_RE.search(line)):
        return _side_record("mmu", index, line, to_float(match.group("ms")) / 1000)
    return None


def scan_side_records(log_lines: Iterable[str]) -> list[SideRecord]:
    """Concurrent-work durations, safepoints and G1 pause-goal misses, in line order."""
    return [
        record
        for index, line in enumerate(log_lines)
        if (record := side_record_for(index, line)) is not None
    ]


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


DETECTION_SAMPLE_LINES = 400


def detect_gc_type_and_create_parser(log_lines: LineSource) -> GCParser:
    """Detect log format family (unified vs. legacy), then the collector, from its first
    ``DETECTION_SAMPLE_LINES`` lines (a shared window keeps them for the parser)."""
    sample_lines = as_window(log_lines).range(0, DETECTION_SAMPLE_LINES)
    if any(is_unified_line(line) for line in sample_lines):
        return _detect_unified_parser(sample_lines)

    for line in sample_lines:
        if line.startswith(("CommandLine flags:", "-XX:")):
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


YOUNG_ABOVE_HEAP = "young generation above the whole heap"


def young_after_full_collection(
    heap: tuple[int, int, int], young: tuple[int, int, int], old_after: int
) -> int:
    """Young generation after a pause that also collected the old generation.

    A young collection that escalates ("[ParNew: 34944K->34944K(39296K), ...][CMS: ...]",
    "[DefNew: ...][Tenured: ...]") logs its young step before the full collection empties
    the young generation, so the young size after the whole pause is the heap after it
    minus the old generation after it. Parallel logs that same figure. The young step's own
    figure is kept when the heap and old sizes do not add up.
    """
    remaining = heap[1] - old_after
    return remaining if 0 <= remaining <= young[2] else young[1]


def old_gen_from_heap_and_young(
    heap: tuple[int, int, int], young: tuple[int, int, int]
) -> tuple[int | None, int | None, int | None]:
    """Old gen = heap - young (before, after, total), for logs that print exact KB.

    A negative result means the record is inconsistent; that value is unknown (None), not 0.
    """
    differences = (heap[0] - young[0], heap[1] - young[1], heap[2] - young[2])
    old = tuple(value if value >= 0 else None for value in differences)
    return old[0], old[1], old[2]
