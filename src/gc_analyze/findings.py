"""Ranked findings: each health warning turned into what, when, evidence and action.

Every warning in ``GCSummary.health_warnings`` ends up in exactly one finding: the builders
below claim the warnings they explain by code, and any warning left over becomes a finding of
its own, so nothing the analysis flagged can go missing from the top of the report.

The findings list is the single source of truth for the report's status and the process exit
code (``overall_status``): a problem that is reported is a problem that counts.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from itertools import pairwise
from statistics import median
from typing import Literal

from .advice import LARGE_HEAP_BYTES, Advice, advice_for, jdk_major
from .analysis import (
    cleaned_floors,
    describe_floor_step,
    format_duration,
    format_mb_per_hour,
    format_size_kb,
    format_time,
    is_heap_pressure_full_gc,
    window_name,
)
from .models import (
    CandidateCoverage,
    Finding,
    FloorPoint,
    GCEvent,
    GCSummary,
    HealthWarning,
)
from .parsers import parse_unified_prefix_times, to_float

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
ROLE_ORDER = {"cause": 0, "symptom": 1, "": 2}
# Explicit Full GCs this evenly spaced come from a timer, not from application logic
PERIODIC_MIN_INTERVALS = 3
PERIODIC_TOLERANCE = 0.05
GCLOCKER_MIN_PAUSES = 5
GCLOCKER_MIN_SHARE = 0.05
LONG_REMARK_SECONDS = 0.5
LONG_PAUSE_SECONDS = 1.0
SECONDARY_NOTE = (
    "Secondary: the heap ran out of room (see the findings above). Fix that first and "
    "revisit this only if it is still there afterwards. "
)


type Severity = Literal["critical", "warning", "info"]
type Status = Literal["critical", "warning", "ok"]


def overall_status(findings: list[Finding]) -> Status:
    """Worst severity among the findings; informational findings do not change the status."""
    if any(f.severity == "critical" for f in findings):
        return "critical"
    if any(f.severity == "warning" for f in findings):
        return "warning"
    return "ok"


def _severity(warnings: list[HealthWarning]) -> Severity:
    return "critical" if any(w.level == "CRITICAL" for w in warnings) else "warning"


def _size(kb: float) -> str:
    return format_size_kb(kb)


def format_pause(seconds: float) -> str:
    """'0.020 s', '1.50 s', '60.0 s': enough digits that a short pause is not shown as 0.0."""
    if seconds < 1:
        return f"{seconds:.3f} s"
    if seconds < 10:
        return f"{seconds:.2f} s"
    return f"{seconds:.1f} s"


def _sources(*advice: Advice) -> str:
    """Each cited reference once, in order (an entry's source can list several)."""
    return "; ".join(dict.fromkeys(ref for a in advice for ref in a.source.split("; ") if ref))


def _when(event: GCEvent) -> str:
    return format_time(event.timestamp, event.wall_clock, event.uptime_seconds)


def _floor_when(point: FloorPoint) -> str:
    return format_time(point.timestamp, point.wall_clock, point.uptime_seconds)


class _Warnings:
    """The summary's warnings, handed out by code to the findings that explain them."""

    def __init__(self, warnings: list[HealthWarning]) -> None:
        self.left = list(warnings)

    def claim(self, *codes: str) -> list[HealthWarning]:
        taken = [w for w in self.left if w.code in codes]
        self.left = [w for w in self.left if w.code not in codes]
        return taken


def explicit_gc_period_seconds(events: list[GCEvent]) -> float | None:
    """Interval between explicit Full GCs when they are evenly spaced, else None."""
    explicit = [
        event for event in events if event.gc_kind == "Full" and event.cause == "System.gc()"
    ]
    if len({event.segment for event in explicit}) != 1:
        return None
    stamps = [event.timestamp for event in explicit]
    gaps = [(later - earlier).total_seconds() for earlier, later in pairwise(stamps)]
    if len(gaps) < PERIODIC_MIN_INTERVALS:
        return None
    typical = median(gaps)
    if typical <= 0 or any(abs(gap - typical) > PERIODIC_TOLERANCE * typical for gap in gaps):
        return None
    return typical


def memory_inspection_advice(summary: GCSummary, major: int | None) -> tuple[str, str]:
    """How to see what holds the memory, scaled to the heap: (text, sources).

    A full dump of a very large heap is slow and as big as the live data, so above
    ``LARGE_HEAP_BYTES`` the class histogram comes first. The OutOfMemoryError dump flag is
    named either as already set or as worth setting.
    """
    heap = summary.heap
    config = summary.jvm_heap_config
    advice: list[Advice] = []
    large = bool(heap.max_heap_kb and heap.max_heap_kb * 1024 >= LARGE_HEAP_BYTES)
    if large:
        histogram = advice_for("class_histogram", major)
        advice.append(histogram)
        text = (
            f"{histogram.text}. A full dump (jcmd <pid> GC.heap_dump <file>) "
            "requests a full GC first and needs disk space and analysis memory on the scale of "
            "the live data"
        )
        advice.append(advice_for("heap_dump", major))
    else:
        advice.append(advice_for("heap_dump", major))
        text = advice_for("heap_dump", major).text
    oom = advice_for("heap_dump_on_oom", major)
    if config and config.heap_dump_on_out_of_memory_error:
        text += (
            ". -XX:+HeapDumpOnOutOfMemoryError is already set, so an OutOfMemoryError will "
            "leave a dump to analyse"
        )
    else:
        text += f". {oom.text}"
    advice.append(oom)
    return text, _sources(*advice)


def _truncated_record_context(record: str, events: list[GCEvent]) -> list[str]:
    """What the JVM was doing just before the unfinished final record."""
    if not events:
        return []
    last = events[-1]
    lines = [
        f"Last finished pause: {last.gc_kind} ({last.cause or 'cause not logged'}), "
        f"{format_pause(last.pause_time_seconds)}, ending at "
        f"{format_time(last.pause_end, last.wall_clock, _end_uptime(last))}"
    ]
    # the sample is "L123: <line>" (with a "file:" prefix for several inputs)
    text = record.split(": ", 1)[1] if ": " in record else record
    uptime: float | None
    if text.startswith("["):
        uptime = parse_unified_prefix_times(text)[1]
    else:
        head = text.split(": [", 1)[0].rsplit(": ", 1)[-1].strip()
        try:
            uptime = to_float(head)
        except ValueError:
            uptime = None
    last_end = _end_uptime(last)
    if uptime is not None and last_end is not None and uptime >= last_end:
        lines.append(
            f"The unfinished collection started {format_pause(uptime - last_end)} after that "
            "pause ended"
        )
    return lines


def _end_uptime(event: GCEvent) -> float | None:
    if event.uptime_seconds is None:
        return None
    if event.stamp_at_pause_end:
        return event.uptime_seconds
    return event.uptime_seconds + event.pause_time_seconds


def _trailing_full_gcs(events: list[GCEvent]) -> int:
    """How many Full GCs the window ends with, back to back."""
    count = 0
    for event in reversed(events):
        if event.gc_kind != "Full":
            break
        count += 1
    return count


def build_findings(
    summary: GCSummary,
    gc_type: str,
    events: list[GCEvent],
    coverage: CandidateCoverage | None = None,
) -> list[Finding]:
    """All findings, most severe first; within a severity causes come before symptoms."""
    warnings = _Warnings(summary.health_warnings)
    findings: list[Finding] = []
    is_g1 = "G1" in gc_type
    is_parallel = "Parallel" in gc_type
    unified = any(e.stamp_at_pause_end for e in events)
    major = jdk_major(summary.environment, unified)
    config = summary.jvm_heap_config
    heap = summary.heap
    trend = summary.floor_trend
    max_heap = (
        f" (max heap is {_size(heap.max_heap_kb)})"
        if heap.max_heap_known and heap.max_heap_kb
        else ""
    )
    inspect_text, inspect_source = memory_inspection_advice(summary, major)
    # The heap ran out of room: everything else in the report follows from that
    exhausted = any(
        (w.code == "heap_occupancy" and w.level == "CRITICAL") or w.code == "ineffective_full_gc"
        for w in summary.health_warnings
    )

    # ---- the log stops inside a collection
    if coverage is not None and coverage.truncated_final_record and summary.includes_log_tail:
        record = coverage.truncated_final_record
        in_full_gc = "Full" in record
        trailing = _trailing_full_gcs(events)
        findings.append(
            Finding(
                severity="critical" if in_full_gc and trailing >= 2 else "warning",
                title=(
                    "The JVM was in back-to-back Full GCs when the log stops, in the middle "
                    "of another one"
                    if in_full_gc and trailing >= 2
                    else "The log ends in the middle of a collection"
                ),
                when="end of the log",
                evidence=[
                    f"Unfinished record in the supplied log: {record}",
                    *_truncated_record_context(record, events),
                    *(
                        [f"The {trailing} pauses before it were all Full GCs"]
                        if trailing >= 2
                        else []
                    ),
                ],
                action=(
                    "Check for the remainder of the log. Correlate that timestamp with service "
                    "restart records, the host journal and JVM crash logs"
                ),
                role="symptom" if exhausted else "",
            )
        )

    # ---- the application was mostly stopped
    if taken := warnings.claim("pause_share"):
        worst = next(w for w in summary.worst_pause_shares if w.window_seconds == 300.0)
        window_end = worst.window_start + timedelta(seconds=300)
        by_kind: dict[str, float] = {}
        for event in events:
            overlap = (
                min(event.pause_end, window_end) - max(event.pause_start, worst.window_start)
            ).total_seconds()
            if overlap > 0:
                label = f"{event.gc_kind} ({event.cause or 'cause not logged'})"
                by_kind[label] = by_kind.get(label, 0.0) + overlap
        evidence = [
            f"Worst {window_name(w.window_seconds)}: {w.share_percentage:.1f}% paused "
            f"({format_duration(w.paused_seconds)}) from "
            f"{format_time(w.window_start, w.wall_clock, w.uptime_seconds)}"
            for w in summary.worst_pause_shares
        ]
        evidence += [
            f"In the worst 5 minutes: {seconds:.0f} s in {label} pauses"
            for label, seconds in sorted(by_kind.items(), key=lambda item: -item[1])[:2]
        ]
        evidence.append(
            f"Whole-window overhead is {summary.gc_overhead_pct:.1f}%, which hides this"
        )
        findings.append(
            Finding(
                severity=_severity(taken),
                title=(
                    f"The application was stopped for {worst.share_percentage:.0f}% of the worst "
                    "5 minutes"
                ),
                when=format_time(worst.window_start, worst.wall_clock, worst.uptime_seconds),
                evidence=evidence,
                action=(
                    "Correlate this stretch with request timeouts, failed health checks and "
                    "upstream queueing. "
                    "The Timeline shows when it began; the other findings explain the pauses "
                    "responsible"
                ),
                role="symptom",
            )
        )

    # ---- live data fills the space
    if taken := warnings.claim("heap_occupancy"):
        if is_g1 or summary.peak_post_full_old is None:
            advice_text, source = (
                "If the application needs this much live data, increase the heap" + max_heap,
                advice_for("g1_full_gc", major).source if is_g1 else "",
            )
        else:
            advice_text, source = (
                advice_for("old_gen_slack", major).text + max_heap,
                advice_for("old_gen_slack", major).source,
            )
        floors = cleaned_floors(trend)[-3:]
        findings.append(
            Finding(
                severity=_severity(taken),
                title="Occupancy remains high after Full GC",
                evidence=[w.text for w in taken]
                + [
                    # cleaned floors are heap occupancy after a Full GC, as % of max heap
                    "Last post-Full-GC heap floors: "
                    + ", ".join(
                        f"{_size(f.value_kb)}"
                        + (
                            f" ({f.pct_of_capacity:.1f}% of max heap)"
                            if f.pct_of_capacity is not None
                            else ""
                        )
                        for f in floors
                    )
                ]
                * bool(floors),
                action=(
                    "First rule out unbounded growth (see the live-set findings) by looking at "
                    f"what holds the memory. {inspect_text}. {advice_text}"
                ),
                source=inspect_source + (f"; {source}" if source else ""),
                role="cause",
            )
        )

    # ---- Full GCs
    if taken := warnings.claim("ineffective_full_gc", "full_gc_streak", "full_gc_rate"):
        # "reclaimed little" is only said when the Full GCs did (a streak alone is frequency)
        struggling = bool(summary.ineffective_full_gc_count)
        streak = any(w.code == "full_gc_streak" for w in taken)
        heap_fulls = [e for e in events if is_heap_pressure_full_gc(e)]
        evidence = [w.text for w in taken]
        if summary.heap_full_gc_reclaimed_pcts:
            shown = summary.heap_full_gc_reclaimed_pcts[-8:]
            evidence.append(
                "Heap freed by the last heap-pressure Full GCs: "
                + ", ".join(f"{pct:.1f}%" for pct in shown)
            )
        # supporting evidence only: neither raises an alarm by itself
        if summary.reclamation_declining:
            evidence.append("Each heap-pressure Full GC frees a smaller share of the heap")
        if summary.full_gc_accelerating:
            evidence.append("The gaps between heap-pressure Full GCs are getting shorter")
        if heap_fulls:
            longest = max(heap_fulls, key=lambda e: e.pause_time_seconds)
            evidence.append(
                f"Longest: {format_pause(longest.pause_time_seconds)} at {_when(longest)} "
                f"({longest.cause or 'cause not logged'})"
            )
        full_gc_sources = [inspect_source] if struggling else []
        action = (
            f"Full GCs reclaimed little while occupancy remained high. {inspect_text}. Then "
            f"either fix what retains the memory or raise -Xmx{max_heap}"
            if struggling
            else "Each heap-pressure Full GC stops the application; find why the old generation "
            "fills (see heap and live-set findings)"
        )
        if is_g1:
            full_gc_sources.append(advice_for("g1_full_gc", major).source)
            action += f". {advice_for('g1_full_gc', major).text}"
            if major is not None and major < 10:
                full_gc_sources.append(advice_for("g1_full_gc_single_threaded", major).source)
                action += f". {advice_for('g1_full_gc_single_threaded', major).text}"
        if is_parallel and summary.ineffective_full_gc_count:
            full_gc_sources.append(advice_for("parallel_overhead_limit", major).source)
            action += f". {advice_for('parallel_overhead_limit', major).text}"
        if not struggling:
            title = (
                "Heap-pressure Full GCs are running back to back"
                if streak
                else "Heap-pressure Full GCs are frequent"
            )
        elif summary.max_full_gc_streak_after_warmup >= 2:
            title = "Back-to-back Full GCs are freeing little memory"
        elif summary.heap_full_gc_count == 1:
            title = "A Full GC freed little memory"
        else:
            title = "Full GCs are freeing little memory"
        findings.append(
            Finding(
                severity=_severity(taken),
                title=title,
                when=f"{_when(heap_fulls[0])} to {_when(heap_fulls[-1])}" if heap_fulls else "",
                evidence=evidence,
                action=action,
                source="; ".join(dict.fromkeys(full_gc_sources)),
                role="cause" if struggling else "symptom",
            )
        )

    # ---- a Full GC streak only while the JVM was starting
    startup_streak = summary.max_full_gc_streak
    if (
        startup_streak >= summary.thresholds.full_gc_streak_count
        and summary.max_full_gc_streak_after_warmup < summary.thresholds.full_gc_streak_count
    ):
        warmup_minutes = summary.thresholds.warmup_seconds / 60
        startup_fulls = [
            e
            for e in events
            if is_heap_pressure_full_gc(e)
            and e.uptime_seconds is not None
            and e.uptime_seconds < summary.thresholds.warmup_seconds
        ]
        findings.append(
            Finding(
                severity="info",
                title=f"{startup_streak} back-to-back heap-pressure Full GCs during JVM start-up",
                when=f"{_when(startup_fulls[0])} to {_when(startup_fulls[-1])}"
                if startup_fulls
                else "",
                evidence=[
                    f"All within the first {warmup_minutes:.0f} min of uptime; none in a "
                    "streak after it",
                    *(
                        [
                            "Heap freed by the heap-pressure Full GCs: "
                            + ", ".join(
                                f"{pct:.1f}%" for pct in summary.heap_full_gc_reclaimed_pcts[-8:]
                            )
                        ]
                        if summary.heap_full_gc_reclaimed_pcts
                        else []
                    ),
                ],
                action=(
                    "Full GCs while the application loads its data at start-up are expected to "
                    "stop once it is running. Look into them if start-up is slow or they "
                    "continue after it"
                ),
                role="symptom",
            )
        )

    # ---- live set
    if taken := warnings.claim("live_set_step"):
        findings.append(
            Finding(
                severity="warning",
                title="Post-GC occupancy jumped between comparable collections",
                when=(
                    f"{_floor_when(trend.step_change.before)} to "
                    f"{_floor_when(trend.step_change.after)}"
                    if trend.step_change
                    else ""
                ),
                evidence=[describe_floor_step(trend) or taken[0].text],
                confidence="medium",
                action=(
                    "Check for a workload or retention change in that "
                    "interval (a very large request or query, a batch job, a cache load) in the "
                    "access and application logs, then look at what holds the memory while the "
                    f"heap is high. {inspect_text}"
                ),
                source=inspect_source,
                role="cause",
            )
        )
    if (taken := warnings.claim("live_set_growing")) and trend.slope_mb_per_hour is not None:
        floors = trend.trend_floors
        findings.append(
            Finding(
                severity=_severity(taken),
                title=(
                    f"{trend.measurement.capitalize()} is rising "
                    f"{format_mb_per_hour(trend.slope_mb_per_hour)}"
                ),
                when=f"{_floor_when(floors[0])} to {_floor_when(floors[-1])}",
                evidence=list(summary.leak.evidence),
                confidence="high"
                if trend.measurement == "post-Full-GC heap occupancy"
                and trend.p_value is not None
                and trend.p_value < 0.01
                and len(floors) >= 10
                else "medium",
                action=(
                    "Check whether load, cache growth or unexpected retention explains the rise. "
                    "Compare what holds the memory at two moments hours apart to see what is "
                    f"growing. {inspect_text}"
                ),
                source=inspect_source,
                role="cause",
            )
        )

    # ---- long pauses
    top = sorted(events, key=lambda e: e.pause_time_seconds, reverse=True)[:10]
    longest_pause = top[0] if top else None
    taken = warnings.claim("p99_pause", "long_pause")
    has_full_gc_finding = any("Full GC" in f.title for f in findings)
    if longest_pause and (taken or longest_pause.pause_time_seconds >= LONG_PAUSE_SECONDS):
        pause_advice: list[Advice] = []
        kind = longest_pause.gc_kind
        if kind == "Full" and has_full_gc_finding:
            action = "The longest pause is a Full GC: act on the Full GC findings"
        elif kind == "Full":
            action = (
                "The longest pause is a Full GC, which stops the application for its whole "
                "length; Full GC Causes shows why each one ran"
            )
        elif kind == "Remark" and is_g1:
            pause_advice.append(advice_for("g1_remark", major))
            action = advice_for("g1_remark", major).text
        elif is_g1:
            pause_advice.append(advice_for("g1_young_pause", major))
            action = advice_for("g1_young_pause", major).text
        else:
            action = "See Top 10 Longest Pauses for the kind and cause of each"
        if taken:
            action = (
                "A pause this long outlasts typical proxy and health-check timeouts: requests "
                f"in flight fail and the node can be taken out of rotation. {action}"
            )
        if (is_parallel or "Serial" in gc_type) and not exhausted:
            pause_advice.append(advice_for("selecting_collector", major))
            action += f". {advice_for('selecting_collector', major).text}"
        over = [
            f"{count} over {label}"
            for label, count in (
                ("1 s", summary.pauses_over_1s),
                ("5 s", summary.pauses_over_5s),
                ("30 s", summary.pauses_over_30s),
                ("60 s", summary.pauses_over_60s),
            )
            if count
        ]
        kinds = Counter(e.gc_kind for e in top)
        p99_of = f"{summary.worst_p99_kind} " if summary.worst_p99_kind else ""
        # the P99 belongs in the title only when it is part of the problem
        p99_text = (
            f"; {p99_of}P99 {format_pause(summary.worst_p99_seconds)}"
            if any(w.code == "p99_pause" for w in taken)
            else ""
        )
        findings.append(
            Finding(
                severity=_severity(taken) if taken else "info",
                title=(
                    f"Pauses are long: longest {format_pause(longest_pause.pause_time_seconds)}"
                    f"{p99_text}"
                ),
                when=f"longest at {_when(longest_pause)}",
                evidence=[
                    *[w.text for w in taken],
                    f"Longest: {longest_pause.gc_kind} "
                    f"({longest_pause.cause or 'cause not logged'})",
                    f"The {len(top)} longest: "
                    + ", ".join(f"{count} {name}" for name, count in kinds.most_common()),
                    *([f"Pauses {', '.join(over)}"] if over else []),
                ],
                action=action,
                source=_sources(*pause_advice),
                role="symptom",
            )
        )
    elif (
        longest_pause
        and is_g1
        and longest_pause.gc_kind == "Remark"
        and longest_pause.pause_time_seconds >= LONG_REMARK_SECONDS
    ):
        remark = summary.pauses_by_kind["Remark"]
        findings.append(
            Finding(
                severity="info",
                title=f"Remark pauses are the longest pauses (up to {remark.maximum:.2f} s)",
                when=f"longest at {_when(longest_pause)}",
                evidence=[
                    f"Remark P99 {remark.p99:.3f} s over {remark.count} pauses; all pauses "
                    f"P99 {summary.overall_pauses.p99:.3f} s"
                ],
                action=advice_for("g1_remark", major).text,
                source=advice_for("g1_remark", major).source,
            )
        )

    if taken := warnings.claim("gc_overhead"):
        rate = (
            f" (allocation rate {summary.allocation_rate_mb_sec:.0f} MB/s)"
            if summary.allocation_rate_mb_sec and summary.allocation_rate_mb_sec >= 1
            else ""
        )
        findings.append(
            Finding(
                severity=_severity(taken),
                title=(
                    f"GC pauses take {summary.gc_overhead_pct:.1f}% of the {summary.window_basis}"
                ),
                evidence=[
                    f"{format_duration(summary.total_gc_time_sec)} paused in "
                    f"{format_duration(summary.runtime_seconds)}"
                ],
                action=(
                    "Check which pause types account for the time. Compare allocation, heap "
                    f"occupancy, and CPU and safepoint timing where available{rate}"
                ),
                role="symptom",
            )
        )

    # ---- stops that are not GC
    if taken := warnings.claim("safepoint_non_gc"):
        stops = summary.safepoint_stats
        # a slow-to-stop warning about the same stop belongs here, not in a second finding
        if stops is not None and stops.longest_stopping_when == stops.longest_non_gc_when:
            taken += warnings.claim("safepoint_slow")
        evidence = [w.text for w in taken]
        if stops is not None and stops.non_gc_count is not None:
            evidence.append(
                f"{stops.non_gc_count} of {stops.count} safepoints are not explained by a GC "
                f"pause; their total elapsed safepoint time was "
                f"{format_pause(stops.non_gc_total_seconds)}"
            )
        findings.append(
            Finding(
                severity=_severity(taken),
                title=(
                    "Non-GC safepoint took "
                    f"{format_pause(stops.longest_non_gc_seconds if stops else 0.0)} elapsed"
                ),
                when=stops.longest_non_gc_when if stops else "",
                evidence=evidence,
                action=(
                    "The VM "
                    "operation names what the JVM stopped for (a thread dump, a heap "
                    "inspection, deoptimization, ...); a long wait to stop the threads means "
                    "some thread did not reach a safepoint promptly. Match the time against "
                    "monitoring agents, scheduled diagnostics and the application's own logs"
                ),
            )
        )

    # ---- premature promotion
    overflow = summary.survivor_overflow
    if (taken := warnings.claim("survivor_overflow")) and overflow is not None:
        survivor = _size(overflow.survivor_capacity_kb)
        survivor_advice = advice_for(
            "survivor_overflow_parallel" if is_parallel else "survivor_overflow", major
        )
        findings.append(
            Finding(
                severity="info" if exhausted else "warning",
                title="Young collections are overflowing the survivor space",
                when=f"{overflow.first_when} to {overflow.last_when}",
                evidence=[
                    *[w.text for w in taken],
                    f"The survivor space was {survivor} and full after each of them",
                ],
                confidence="medium",
                action=(SECONDARY_NOTE if exhausted else "")
                + (
                    f"{survivor_advice.text}. If the live-set findings show the "
                    "application keeping everything it allocates, a larger survivor space only "
                    "delays the old generation filling"
                ),
                source=survivor_advice.source,
                role="symptom" if exhausted else "",
            )
        )

    # ---- promotion failure (any generational collector) and CMS fallback
    promotion = warnings.claim("promotion_failure")
    cms_failure = warnings.claim("cms_concurrent_mode_failure")
    if cms_failure or (promotion and "CMS" in gc_type):
        # A Java 8 CMS young collection that escalates logs its ParNew step and then the
        # CMS step in the same record; a "[Full GC" record has no young step. (Unified logs
        # give every pause young sizes from the heap lines, so they cannot show this.)
        escalated = sum(
            1
            for e in events
            if e.gc_kind == "Full" and e.young_before_kb is not None and not e.stamp_at_pause_end
        )
        young_attempts = escalated + sum(1 for e in events if e.gc_kind == "Young")
        evidence = [w.text for w in cms_failure + promotion]
        if escalated:
            evidence.append(
                f"{escalated} of {young_attempts} young collections ended as a stop-the-world "
                "collection of the whole heap"
            )
        findings.append(
            Finding(
                severity=_severity(cms_failure + promotion),
                title="CMS fell back to stop-the-world collections",
                evidence=evidence,
                action=advice_for("cms_concurrent_mode_failure", major).text,
                source=advice_for("cms_concurrent_mode_failure", major).source,
                role="symptom" if exhausted else "",
            )
        )
    elif promotion:
        failed = [e for e in events if e.promotion_failed]
        findings.append(
            Finding(
                severity=_severity(promotion),
                title=f"{len(failed)} young collection(s) ended in a promotion failure",
                when=", ".join(_when(e) for e in failed[:3]) + (" ..." if len(failed) > 3 else ""),
                evidence=[
                    *[w.text for w in promotion],
                    "Longest of them: " + format_pause(max(e.pause_time_seconds for e in failed)),
                ],
                action=(
                    "A promotion failure means the old generation had no room for the objects "
                    "surviving a young collection; a Full GC normally follows. The old "
                    "generation is too full: act on the heap, Full GC and live-set findings"
                ),
                role="symptom",
            )
        )

    # ---- G1 specifics
    failed = [e for e in events if e.evacuation_failed]
    taken = warnings.claim("g1_evacuation_failure")
    if failed:
        startup_only = not taken
        reasons: dict[str, int] = {}
        for event in failed:
            reason = event.evacuation_failure_reason or (
                "Allocation" if event.to_space_exhausted else "reason unavailable"
            )
            reasons[reason] = reasons.get(reason, 0) + 1
        evidence = [", ".join(f"{count} {reason}" for reason, count in reasons.items())]
        evidence.extend(w.text for w in taken)
        advice: list[Advice] = []
        reasons_logged = {part for reason in reasons for part in reason.split("/")}
        if "Allocation" in reasons_logged:
            advice.append(advice_for("g1_evacuation_failure", major))
        if "Pinned" in reasons_logged:
            advice.append(advice_for("g1_pinned", major))
        if reasons_logged - {"Allocation", "Pinned"}:
            advice.append(advice_for("g1_evacuation_unknown", major))
        findings.append(
            Finding(
                severity="info" if startup_only else _severity(taken),
                title=f"{len(failed)} G1 evacuation failure(s)"
                + (" during JVM start-up" if startup_only else ""),
                when=", ".join(_when(event) for event in failed[:3])
                + (" ..." if len(failed) > 3 else ""),
                evidence=evidence,
                confidence="high" if "reason unavailable" not in reasons else "medium",
                action=". ".join(item.text for item in advice),
                source=_sources(*advice),
                role="symptom",
            )
        )

    if taken := warnings.claim("g1_humongous"):
        evidence = [w.text for w in taken]
        if config and config.g1_heap_region_size_bytes:
            evidence.append(
                f"Region size is {config.g1_heap_region_size_bytes // 1048576} MiB. "
                f"Objects larger than {config.g1_heap_region_size_bytes / 2097152:g} MiB "
                "are humongous"
            )
        findings.append(
            Finding(
                severity="warning",
                title="Humongous objects take a large share of the G1 heap",
                evidence=evidence,
                action=advice_for("g1_humongous", major).text,
                source=_sources(advice_for("g1_humongous", major)),
            )
        )
    marking_claimed = warnings.claim("concurrent_share")
    g1_metrics = summary.g1_metrics
    frequent_marking = (
        g1_metrics is not None
        and g1_metrics.marking_cycles_per_hour is not None
        and g1_metrics.marking_cycles_per_hour >= FREQUENT_MARKING_CYCLES_PER_HOUR
    )
    if marking_claimed or frequent_marking:
        evidence = [w.text for w in marking_claimed]
        concurrent = summary.concurrent_stats
        if g1_metrics is not None and g1_metrics.concurrent_marking_cycles:
            cycles = g1_metrics.concurrent_marking_cycles
            line = f"{cycles} marking cycles"
            if summary.runtime_seconds:
                line += f", one every {format_duration(summary.runtime_seconds / cycles)}"
            if concurrent and concurrent.share_percentage is not None:
                line += (
                    f"; concurrent work ran for {concurrent.share_percentage:.1f}% of the window"
                )
            evidence.append(line)
            if g1_metrics.median_marking_start_pct is not None:
                evidence.append(
                    "Marking starts with the old generation at a median "
                    f"{g1_metrics.median_marking_start_pct:.0f}% of max heap"
                )
            floors_pct = [
                f.pct_of_capacity for f in cleaned_floors(trend) if f.pct_of_capacity is not None
            ]
            if floors_pct:
                evidence.append(
                    f"Post-Full-GC occupancy was a median {median(floors_pct):.0f}% of max heap"
                )
            if g1_metrics.mixed_per_marking_cycle is not None:
                evidence.append(
                    f"{g1_metrics.mixed_per_marking_cycle:.1f} mixed collections per marking cycle"
                )
            if g1_metrics.concurrent_start_count and g1_metrics.humongous_concurrent_start_count:
                humongous_note = (
                    f"{g1_metrics.humongous_concurrent_start_count} of "
                    f"{g1_metrics.concurrent_start_count} cycles were started by a pause with "
                    'the cause "G1 Humongous Allocation". G1 checks the threshold at every '
                    "humongous allocation, so the cause names when the threshold was noticed, "
                    "not why it was exceeded"
                )
                if (
                    g1_metrics.typical_humongous_pct is not None
                    and g1_metrics.peak_humongous_pct is not None
                ):
                    humongous_note += (
                        " (humongous objects typically held "
                        f"{g1_metrics.typical_humongous_pct:.1f}% of the heap, at most "
                        f"{g1_metrics.peak_humongous_pct:.1f}%)"
                    )
                evidence.append(humongous_note)
        findings.append(
            Finding(
                severity="warning" if marking_claimed else "info",
                title=(
                    "G1 marking cycles were frequent"
                    if is_g1
                    else "The collector is marking almost continuously"
                ),
                evidence=evidence,
                confidence="medium",
                action=(
                    advice_for("g1_marking_threshold", major).text
                    if is_g1
                    else "Concurrent cycles start whenever old-generation occupancy passes the "
                    "initiating threshold, so live data sitting near that threshold keeps them "
                    "running. A larger heap lowers the occupancy"
                ),
                source=advice_for("g1_marking_threshold", major).source if is_g1 else "",
            )
        )

    # ---- metaspace
    if taken := warnings.claim("metaspace_full_gc"):
        current = (
            f" (currently {config.metaspace_size_bytes // 1048576} MB)"
            if config and config.metaspace_size_bytes
            else ""
        )
        findings.append(
            Finding(
                severity="info" if exhausted else "warning",
                title=f"{summary.metadata_full_gc_count} Full GC(s) were triggered by metaspace",
                evidence=[w.text for w in taken],
                action=(SECONDARY_NOTE if exhausted else "")
                + advice_for("metaspace_threshold", major).text
                + current,
                source=advice_for("metaspace_threshold", major).source,
            )
        )
    if taken := warnings.claim("metaspace_usage"):
        findings.append(
            Finding(
                severity="warning",
                title="Metaspace keeps growing or is near its limit",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=advice_for("metaspace_limit", major).text,
                source=advice_for("metaspace_limit", major).source,
            )
        )

    # ---- operating system
    if taken := warnings.claim("cpu_kernel"):
        already: list[str] = []
        if (
            config
            and config.initial_heap_size_bytes
            and config.initial_heap_size_bytes == config.max_heap_size_bytes
        ):
            already.append("-Xms already equals -Xmx here")
        if config and config.always_pre_touch:
            already.append("pre-touch is already on")
        note = f" ({'; '.join(already)})" if already else ""
        findings.append(
            Finding(
                severity="warning",
                title="GC pauses are spending their time in the kernel",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=advice_for("high_sys_time", major).text + note,
                source=advice_for("high_sys_time", major).source,
            )
        )
    if taken := warnings.claim("cpu_waiting"):
        findings.append(
            Finding(
                severity="warning",
                title="GC pauses are waiting rather than working",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=advice_for("off_cpu", major).text,
                source=advice_for("off_cpu", major).source,
            )
        )
    if taken := warnings.claim("safepoint_slow"):
        findings.append(
            Finding(
                severity="warning",
                title="Application threads were slow to reach a safepoint",
                evidence=[w.text for w in taken],
                action=(
                    "Time to reach a safepoint is not GC work, so heap tuning will not shorten "
                    "it. Compare the stopped times with the GC pause times in the Safepoints "
                    "section and look at what the application threads were doing then"
                ),
            )
        )
    if taken := warnings.claim("heap_exceeds_physical"):
        findings.append(
            Finding(
                severity="warning",
                title="The maximum heap is larger than the host's memory",
                evidence=[w.text for w in taken],
                action="Lower -Xmx or give the host more memory; a heap that swaps makes every "
                "collection slow",
            )
        )

    # ---- warnings no builder above explains
    findings += [Finding(severity=_severity([w]), title=w.text) for w in warnings.left]

    # ---- informational
    basis = "max heap" if heap.max_heap_known else "committed heap"
    if (
        not trend.trend_floors
        and len(summary.max_heap_by_segment) <= 1
        and heap.events_with_heap_data
        and heap.peak_after_gc_pct > HEAP_NOT_COLLECTED_NOTE_PERCENTAGE
    ):
        bound = summary.live_set_bound
        evidence = [
            f"Heap after GC peaked at {heap.peak_after_gc_pct:.1f}% of {basis}; that figure "
            "can include unreclaimed objects",
            f"Floors: {trend.reason or 'none in this window'}",
        ]
        if bound.assessed and bound.direction == "rising":
            evidence.append(
                f"Lowest heap after GC rose from {_size(bound.first_kb)} to "
                f"{_size(bound.last_kb)} over {bound.span_hours:.1f} h"
            )
        findings.append(
            Finding(
                severity="info",
                title=("High post-GC occupancy with insufficient retention evidence"),
                evidence=evidence,
                confidence="high",
                action=(
                    "Look for comparable post-collection samples and correlate the timing with "
                    "workload or deployment changes before changing heap settings"
                ),
            )
        )
    if summary.explicit_full_gc_count:
        period = explicit_gc_period_seconds(events)
        explicit_pause = sum(
            c.total_pause_seconds for c in summary.full_gc_causes if c.category == "explicit"
        )
        explicit_advice = (
            [advice_for("explicit_gc_g1", major) if is_g1 else advice_for("explicit_gc", major)]
            if any(c.cause == "System.gc()" for c in summary.full_gc_causes)
            else [advice_for("tool_requested_gc", major)]
        )
        causes = ", ".join(
            f"{c.count} {c.cause}" for c in summary.full_gc_causes if c.category == "explicit"
        )
        evidence = [
            f"{summary.explicit_full_gc_count} Full GC(s) not caused by heap pressure "
            f"({causes}), {format_pause(explicit_pause)} paused in total"
        ]
        if period is not None:
            explicit_advice.insert(0, advice_for("rmi_dgc", major))
            if major is not None and major <= 8:
                explicit_advice.append(advice_for("tomcat_gc_daemon", major))
            evidence.append(f"System.gc() Full GCs recur about every {format_duration(period)}")
        findings.append(
            Finding(
                severity="info",
                title="Periodic explicit GC observed"
                if period is not None
                else "Full GCs are being requested explicitly",
                evidence=evidence,
                confidence="medium" if period is not None else "high",
                action=". ".join(a.text for a in explicit_advice),
                source=_sources(*explicit_advice),
            )
        )
    gclocker = [e for e in events if e.cause == "GCLocker Initiated GC"]
    if len(gclocker) >= GCLOCKER_MIN_PAUSES and len(gclocker) >= GCLOCKER_MIN_SHARE * len(events):
        findings.append(
            Finding(
                severity="info",
                title=f"{len(gclocker)} collections were held up by JNI critical regions",
                evidence=[
                    f"{len(gclocker)} of {len(events)} pauses have the cause GCLocker Initiated GC"
                ],
                action=advice_for("gclocker", major).text,
                source=advice_for("gclocker", major).source,
            )
        )

    findings.sort(key=lambda f: (SEVERITY_ORDER[f.severity], ROLE_ORDER[f.role]))
    return findings


# G1 marking cycles this frequent (per hour) are reported even without a health warning
FREQUENT_MARKING_CYCLES_PER_HOUR = 6.0
# Heap-after-GC above this with no cleaning collection gets the "live set unknown" note
HEAP_NOT_COLLECTED_NOTE_PERCENTAGE = 80.0


def build_diagnosis(
    summary: GCSummary, findings: list[Finding], coverage: CandidateCoverage | None = None
) -> str:
    """One paragraph that puts the cause first and the consequences after it.

    Only written when a finding names a cause; otherwise the findings list speaks for itself.
    """
    if not any(f.role == "cause" and f.severity != "info" for f in findings):
        return ""
    trend = summary.floor_trend
    floors = trend.trend_floors
    parts: list[str] = []
    step = trend.step_change
    if step is not None:
        parts.append(
            f"Post-GC occupancy jumped from {_size(step.before.value_kb)} to "
            f"{_size(step.after.value_kb)} between {_floor_when(step.before)} and "
            f"{_floor_when(step.after)}"
        )
    elif summary.leak.verdict == "growing" and trend.slope_mb_per_hour is not None:
        parts.append(
            f"{trend.measurement.capitalize()} rose {format_mb_per_hour(trend.slope_mb_per_hour)} "
            f"over {trend.span_hours:.1f} h (from {_size(floors[0].value_kb)} to "
            f"{_size(floors[-1].value_kb)})"
        )
    if (
        trend.measurement == "post-Full-GC heap occupancy"
        and floors
        and floors[-1].pct_of_capacity is not None
    ):
        of = (
            "the old generation"
            if trend.capacity_source == "old generation capacity"
            else "the heap"
        )
        latest = floors[-1].pct_of_capacity
        if latest > 80:
            parts.append(f"post-Full-GC occupancy reached {latest:.1f}% of {of}")
    if summary.ineffective_full_gc_count:
        limit = summary.thresholds.ineffective_full_gc_reclaim_percentage
        parts.append(
            f"{summary.ineffective_full_gc_count} of {summary.heap_full_gc_count} heap-pressure "
            f"Full GCs freed less than {limit:g}% of the heap"
        )
    worst = next((w for w in summary.worst_pause_shares if w.window_seconds == 300.0), None)
    if worst is not None and worst.share_percentage > 25:
        parts.append(
            f"in the worst 5 minutes (from "
            f"{format_time(worst.window_start, worst.wall_clock, worst.uptime_seconds)}) the "
            f"application was stopped {worst.share_percentage:.0f}% of the time"
        )
    if coverage is not None and coverage.truncated_final_record and summary.includes_log_tail:
        parts.append("the supplied files end with an unfinished GC record")
    if not parts:
        return ""
    text = "; ".join(parts)
    return text[0].upper() + text[1:] + "."
