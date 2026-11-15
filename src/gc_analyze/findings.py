"""Ranked findings: each health warning turned into what, when, evidence and action.

Every warning in ``GCSummary.health_warnings`` ends up in exactly one finding: the builders
below claim the warnings they explain by code, and any warning left over becomes a finding of
its own, so nothing the analysis flagged can go missing from the top of the report.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from itertools import pairwise
from statistics import median
from typing import Literal

from .advice import ADVICE, Advice, jdk_major
from .analysis import (
    describe_floor_step,
    format_duration,
    format_mb_per_hour,
    format_time,
    is_heap_pressure_full_gc,
)
from .models import (
    CandidateCoverage,
    Finding,
    FloorPoint,
    GCEvent,
    GCSummary,
    HealthWarning,
)

SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}
# Explicit Full GCs this evenly spaced come from a timer, not from application logic
PERIODIC_MIN_INTERVALS = 3
PERIODIC_TOLERANCE = 0.05
GCLOCKER_MIN_PAUSES = 5
GCLOCKER_MIN_SHARE = 0.05
LONG_REMARK_SECONDS = 0.5
LONG_PAUSE_SECONDS = 1.0


Severity = Literal["critical", "warning", "info"]


def _severity(warnings: list[HealthWarning]) -> Severity:
    return "critical" if any(w.level == "CRITICAL" for w in warnings) else "warning"


def _size(kb: float) -> str:
    return f"{kb / 1048576:.2f} GB" if kb >= 1048576 else f"{kb / 1024:.0f} MB"


def _sources(*advice: Advice) -> str:
    return "; ".join(dict.fromkeys(a.source for a in advice))


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
    stamps = [e.timestamp for e in events if e.gc_kind == "Full" and e.cause == "System.gc()"]
    gaps = [(later - earlier).total_seconds() for earlier, later in pairwise(stamps)]
    if len(gaps) < PERIODIC_MIN_INTERVALS:
        return None
    typical = median(gaps)
    if typical <= 0 or any(abs(gap - typical) > PERIODIC_TOLERANCE * typical for gap in gaps):
        return None
    return typical


def build_findings(
    summary: GCSummary,
    gc_type: str,
    events: list[GCEvent],
    coverage: CandidateCoverage | None = None,
) -> list[Finding]:
    """All findings, most severe first (order within a severity is by importance)."""
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
    dump = ADVICE["heap_dump"]

    # ---- the log stops inside a collection
    if coverage is not None and coverage.truncated_final_record:
        record = coverage.truncated_final_record
        findings.append(
            Finding(
                severity="critical" if "Full" in record else "warning",
                title="The log ends in the middle of a collection",
                when="end of the log",
                evidence=[f"Last record, never finished: {record}"],
                action=(
                    "Find out what stopped the JVM at that moment: a kill or restart (service "
                    "manager, operator, health check), the kernel OOM killer (dmesg / journal), "
                    "or a crash (hs_err_pid*.log). If the JVM was still running, the log was "
                    "copied while a collection was in progress"
                ),
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
            f"Worst {format_duration(w.window_seconds)}: {w.share_percentage:.1f}% paused "
            f"({w.paused_seconds:.0f} s) from "
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
                    "During such a stretch the server answers almost nothing: expect request "
                    "timeouts, failed health checks and exhausted connection pools upstream. "
                    "The Timeline shows when it began; the findings below explain the pauses "
                    "responsible"
                ),
            )
        )

    # ---- live data fills the space
    if taken := warnings.claim("heap_occupancy"):
        if is_g1 or trend.metric == "heap":
            advice_text, source = (
                "If the application needs this much live data, increase the heap" + max_heap,
                ADVICE["g1_full_gc"].source if is_g1 else "",
            )
        else:
            advice_text, source = (
                ADVICE["old_gen_slack"].text + max_heap,
                ADVICE["old_gen_slack"].source,
            )
        floors = trend.trend_floors[-3:]
        findings.append(
            Finding(
                severity=_severity(taken),
                title="Live data nearly fills the heap after a full cleanup",
                evidence=[w.text for w in taken]
                + [
                    "Last floors: "
                    + ", ".join(
                        f"{_size(f.value_kb)}"
                        + (f" ({f.pct_of_capacity:.1f}%)" if f.pct_of_capacity is not None else "")
                        for f in floors
                    )
                ]
                * bool(floors),
                action=(
                    "First rule out unbounded growth with a heap dump (jcmd <pid> GC.heap_dump "
                    f"<file>) and the live-set findings. {advice_text}"
                ),
                source=_sources(dump) + (f"; {source}" if source else ""),
            )
        )

    # ---- Full GCs
    if taken := warnings.claim(
        "ineffective_full_gc",
        "full_gc_streak",
        "reclamation_declining",
        "full_gc_accelerating",
        "full_gc_rate",
    ):
        struggling = bool(summary.ineffective_full_gc_count) or any(
            w.code in ("full_gc_streak", "reclamation_declining") for w in taken
        )
        heap_fulls = [e for e in events if is_heap_pressure_full_gc(e)]
        evidence = [w.text for w in taken]
        if summary.heap_full_gc_reclaimed_pcts:
            shown = summary.heap_full_gc_reclaimed_pcts[-8:]
            evidence.append(
                "Heap freed by the last heap-pressure Full GCs: "
                + ", ".join(f"{pct:.1f}%" for pct in shown)
            )
        if heap_fulls:
            longest = max(heap_fulls, key=lambda e: e.pause_time_seconds)
            evidence.append(
                f"Longest: {longest.pause_time_seconds:.1f} s at {_when(longest)} "
                f"({longest.cause or 'cause not logged'})"
            )
        full_gc_advice: list[Advice] = [dump]
        action = (
            f"The heap cannot hold what the application is keeping. {dump.text}. Then either "
            f"fix what retains the memory or raise -Xmx{max_heap}"
            if struggling
            else "Each heap-pressure Full GC stops the application; find why the old generation "
            "fills (see heap and live-set findings)"
        )
        if is_g1:
            full_gc_advice.append(ADVICE["g1_full_gc"])
            action += f". {ADVICE['g1_full_gc'].text}"
            if major is not None and major < 10:
                full_gc_advice.append(ADVICE["g1_full_gc_single_threaded"])
                action += f". {ADVICE['g1_full_gc_single_threaded'].text}"
        if is_parallel and summary.ineffective_full_gc_count:
            full_gc_advice.append(ADVICE["parallel_overhead_limit"])
            action += f". {ADVICE['parallel_overhead_limit'].text}"
        findings.append(
            Finding(
                severity=_severity(taken),
                title=(
                    "Back-to-back Full GCs are freeing little memory"
                    if struggling
                    else "Heap-pressure Full GCs are frequent"
                ),
                when=f"{_when(heap_fulls[0])} to {_when(heap_fulls[-1])}" if heap_fulls else "",
                evidence=evidence,
                action=action,
                source=_sources(*full_gc_advice) if struggling or is_g1 else "",
            )
        )

    # ---- live set
    if taken := warnings.claim("live_set_step"):
        findings.append(
            Finding(
                severity="warning",
                title="The live set jumped between two collections",
                when=(
                    f"{_floor_when(trend.step_change.before)} to "
                    f"{_floor_when(trend.step_change.after)}"
                    if trend.step_change
                    else ""
                ),
                evidence=[describe_floor_step(trend) or taken[0].text],
                confidence="medium",
                action=(
                    "This is sudden retention, not a slow leak. Find what started in that "
                    "interval (a very large request or query, a batch job, a cache load) in the "
                    "access and application logs. A heap dump taken while the heap is high "
                    "shows what holds the memory (jcmd <pid> GC.heap_dump <file>; it requests "
                    "a full GC first)"
                ),
                source=dump.source,
            )
        )
    rising = (
        trend.assessed
        and (trend.slope_mb_per_hour or 0.0) > 0
        and (trend.r_squared or 0.0) >= 0.5
        and summary.leak_severity.severity_level != "None"
    )
    if rising and trend.slope_mb_per_hour is not None:
        level = summary.leak_severity.severity_level
        floors = trend.trend_floors
        findings.append(
            Finding(
                severity="critical" if level in ("High", "Critical") else "warning",
                title=f"The live set is growing {format_mb_per_hour(trend.slope_mb_per_hour)}",
                when=f"over {trend.span_hours:.1f} h",
                evidence=[
                    f"Floor after cleanup went from {_size(floors[0].value_kb)} to "
                    f"{_size(floors[-1].value_kb)} over {len(floors)} floors "
                    f"(fit r²={trend.r_squared:.2f})",
                    *summary.leak_severity.indicators,
                ],
                confidence="high"
                if (trend.r_squared or 0.0) >= 0.8 and len(floors) >= 6
                else "medium",
                action=(
                    "Growth like this is a leak, a cache that is still filling, or rising load. "
                    "Take two heap dumps hours apart and compare retained sizes to see what is "
                    f"growing ({dump.text[0].lower()}{dump.text[1:]})"
                ),
                source=dump.source,
            )
        )

    # ---- long pauses
    top = sorted(events, key=lambda e: e.pause_time_seconds, reverse=True)[:10]
    dominant = Counter(e.gc_kind for e in top).most_common(1)[0][0] if top else ""
    longest_pause = top[0] if top else None
    taken = warnings.claim("p99_pause")
    if longest_pause and (taken or longest_pause.pause_time_seconds >= LONG_PAUSE_SECONDS):
        pause_advice: list[Advice] = []
        if dominant == "Full":
            action = "The longest pauses are Full GCs: act on the Full GC findings"
        elif dominant == "Remark" and is_g1:
            pause_advice.append(ADVICE["g1_remark"])
            action = ADVICE["g1_remark"].text
        elif is_g1:
            pause_advice.append(ADVICE["g1_young_pause"])
            action = ADVICE["g1_young_pause"].text
        else:
            action = "See Top 10 Longest Pauses for the kind and cause of each"
        if is_parallel or "Serial" in gc_type:
            pause_advice.append(ADVICE["selecting_collector"])
            action += f". {ADVICE['selecting_collector'].text}"
        over = [
            f"{count} over {label}"
            for label, count in (
                ("1 s", summary.pauses_over_1s),
                ("5 s", summary.pauses_over_5s),
                ("60 s", summary.pauses_over_60s),
            )
            if count
        ]
        findings.append(
            Finding(
                severity=_severity(taken) if taken else "info",
                title=(
                    f"Pauses are long: P99 {summary.overall_pauses.p99:.1f} s, longest "
                    f"{longest_pause.pause_time_seconds:.1f} s"
                ),
                when=f"longest at {_when(longest_pause)}",
                evidence=[
                    f"Longest: {longest_pause.gc_kind} "
                    f"({longest_pause.cause or 'cause not logged'})",
                    f"The 10 longest are mostly {dominant} pauses",
                    *([f"Pauses {', '.join(over)}"] if over else []),
                ],
                action=action,
                source=_sources(*pause_advice),
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
                action=ADVICE["g1_remark"].text,
                source=ADVICE["g1_remark"].source,
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
                title=f"GC pauses take {summary.gc_overhead_pct:.1f}% of the whole window",
                evidence=[
                    f"{summary.total_gc_time_sec:.0f} s paused in "
                    f"{format_duration(summary.runtime_seconds)}"
                ],
                action=(
                    "Sustained overhead means the heap is too small for what the application "
                    "allocates and keeps: act on the heap and Full GC findings first, then "
                    f"reduce allocation{rate}"
                ),
            )
        )

    # ---- premature promotion
    overflow = summary.survivor_overflow
    if (taken := warnings.claim("survivor_overflow")) and overflow is not None:
        survivor = _size(overflow.survivor_capacity_kb)
        findings.append(
            Finding(
                severity="warning",
                title="Young collections are overflowing the survivor space",
                when=f"{overflow.first_when} to {overflow.last_when}",
                evidence=[
                    *[w.text for w in taken],
                    f"The survivor space was {survivor} and full after each of them",
                ],
                confidence="medium",
                action=(
                    f"{ADVICE['survivor_overflow'].text}. If the live-set findings show the "
                    "application keeping everything it allocates, a larger survivor space only "
                    "delays the old generation filling"
                ),
                source=ADVICE["survivor_overflow"].source,
            )
        )

    # ---- G1 specifics
    if taken := warnings.claim("g1_evacuation_failure"):
        failed = [e for e in events if e.evacuation_failed]
        findings.append(
            Finding(
                severity=_severity(taken),
                title=f"{len(failed)} G1 evacuation failure(s)",
                when=", ".join(_when(e) for e in failed[:3]) + (" ..." if len(failed) > 3 else ""),
                evidence=[w.text for w in taken],
                confidence="high" if len(failed) > 1 else "medium",
                action=ADVICE["g1_evacuation_failure"].text,
                source=ADVICE["g1_evacuation_failure"].source,
            )
        )
    if taken := warnings.claim("g1_humongous"):
        evidence = [w.text for w in taken]
        if config and config.g1_heap_region_size_bytes:
            evidence.append(
                f"Region size is {config.g1_heap_region_size_bytes // 1048576} MB, so objects of "
                f"{config.g1_heap_region_size_bytes // 2097152 or 0.5} MB or more are humongous"
            )
        concurrent = summary.concurrent_stats
        if concurrent and concurrent.cycles > 1 and summary.runtime_seconds:
            evidence.append(
                f"{concurrent.cycles} concurrent cycles, one every "
                f"{format_duration(summary.runtime_seconds / concurrent.cycles)}"
            )
        findings.append(
            Finding(
                severity="warning",
                title="Humongous allocations drive a large share of the collections",
                evidence=evidence,
                action=ADVICE["g1_humongous"].text,
                source=_sources(ADVICE["g1_humongous"]),
            )
        )
    if taken := warnings.claim("concurrent_share"):
        findings.append(
            Finding(
                severity="warning",
                title="The collector is marking almost continuously",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=(
                    "Marking starts whenever old-generation occupancy passes the initiating "
                    "threshold, so live data sitting near that threshold keeps it running. "
                    "A larger heap lowers the occupancy; fewer humongous allocations lower it too"
                ),
                source=ADVICE["g1_humongous"].source if is_g1 else "",
            )
        )

    # ---- CMS
    if taken := warnings.claim("cms_concurrent_mode_failure", "cms_promotion_failure"):
        findings.append(
            Finding(
                severity=_severity(taken),
                title="CMS fell back to stop-the-world collections",
                evidence=[w.text for w in taken],
                action=ADVICE["cms_concurrent_mode_failure"].text,
                source=ADVICE["cms_concurrent_mode_failure"].source,
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
                severity="warning",
                title=f"{summary.metadata_full_gc_count} Full GC(s) were triggered by metaspace",
                evidence=[w.text for w in taken],
                action=ADVICE["metaspace_threshold"].text + current,
                source=ADVICE["metaspace_threshold"].source,
            )
        )
    if taken := warnings.claim("metaspace_usage"):
        findings.append(
            Finding(
                severity="warning",
                title="Metaspace keeps growing or is near its limit",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=ADVICE["metaspace_limit"].text,
                source=ADVICE["metaspace_limit"].source,
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
                action=ADVICE["high_sys_time"].text + note,
                source=ADVICE["high_sys_time"].source,
            )
        )
    if taken := warnings.claim("cpu_waiting"):
        findings.append(
            Finding(
                severity="warning",
                title="GC pauses are waiting rather than working",
                evidence=[w.text for w in taken],
                confidence="medium",
                action=ADVICE["off_cpu"].text,
                source=ADVICE["off_cpu"].source,
            )
        )
    if taken := warnings.claim("safepoint_slow"):
        findings.append(
            Finding(
                severity="warning",
                title="The application was frozen before collections even started",
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
    if summary.explicit_full_gc_count:
        period = explicit_gc_period_seconds(events)
        explicit_pause = sum(
            c.total_pause_seconds for c in summary.full_gc_causes if c.category == "explicit"
        )
        explicit_advice = [ADVICE["explicit_gc_g1"] if is_g1 else ADVICE["explicit_gc"]]
        evidence = [
            f"{summary.explicit_full_gc_count} explicit Full GC(s), "
            f"{explicit_pause:.1f} s "
            "paused in total"
        ]
        if period is not None:
            explicit_advice.insert(0, ADVICE["rmi_dgc"])
            evidence.append(f"They come every {format_duration(period)}, as from a timer")
        findings.append(
            Finding(
                severity="info",
                title="Full GCs are being requested explicitly",
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
                action=ADVICE["gclocker"].text,
                source=ADVICE["gclocker"].source,
            )
        )

    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return findings
