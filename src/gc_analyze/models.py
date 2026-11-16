"""Pydantic models and type aliases for normalized GC events and summaries."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

type GCKind = Literal["Young", "Mixed", "Full", "Initial Mark", "Remark", "Cleanup"]
type FullGCCategory = Literal["heap", "explicit", "metadata"]
type KilobytesValue = int
type PercentageValue = float
type SecondsValue = float

# Pause kinds in report order
GC_KINDS: tuple[GCKind, ...] = ("Young", "Mixed", "Full", "Initial Mark", "Remark", "Cleanup")


class GCEvent(BaseModel):
    """One stop-the-world GC pause, normalized across collectors and log formats."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime
    # None for datestamp-only legacy logs (no -XX:+PrintGCTimeStamps)
    uptime_seconds: float | None
    gc_kind: GCKind
    # False when the log has no wall-clock time and no --jvm-start anchor was given:
    # timestamp is then UPTIME_EPOCH + uptime (correct for intervals, meaningless as a date).
    wall_clock: bool = True
    # Datestamp exactly as logged, and how its zone is known: "in-line" (offset in the log),
    # "cli:<offset>" (--jvm-start), "assumed:UTC" (no offset), None (no wall clock)
    timestamp_raw: str | None = None
    tz_source: str | None = None
    pause_time_seconds: SecondsValue
    # Unified logging (JDK 9+) stamps the line when the pause ENDS; Java 8 logs stamp its start.
    stamp_at_pause_end: bool = False
    # GC cause as logged, e.g. "Allocation Failure", "System.gc()", "G1 Evacuation Pause"
    cause: str | None = None

    # False for pauses logged without heap sizes (e.g. Java 8 G1 remark): heap fields are 0
    # and the event is excluded from heap statistics but kept for pause statistics.
    has_heap_data: bool = True
    heap_before_kb: KilobytesValue
    heap_after_kb: KilobytesValue
    heap_total_kb: KilobytesValue
    heap_used_percentage: PercentageValue

    young_before_kb: KilobytesValue | None = None
    young_after_kb: KilobytesValue | None = None
    young_total_kb: KilobytesValue | None = None

    old_before_kb: KilobytesValue | None = None
    old_after_kb: KilobytesValue | None = None
    old_total_kb: KilobytesValue | None = None
    old_used_percentage: PercentageValue | None = None

    # G1
    humongous_detected: bool = False
    evacuation_failed: bool = False
    to_space_exhausted: bool = False
    # CMS / generational
    concurrent_mode_failure: bool = False
    promotion_failed: bool = False

    # G1 pause that also starts concurrent marking ("Concurrent Start" / "initial-mark")
    concurrent_start: bool = False
    # G1 humongous regions before/after the pause (unified logs with gc+heap region counts)
    humongous_before_kb: KilobytesValue | None = None
    humongous_after_kb: KilobytesValue | None = None
    # Growth of G1 "Old regions" alone across the pause: what a young collection promoted.
    # (old_after - old_before also contains humongous regions freed in the same pause.)
    promoted_kb: KilobytesValue | None = None

    # Metaspace
    metaspace_before_kb: KilobytesValue | None = None
    metaspace_after_kb: KilobytesValue | None = None
    metaspace_total_kb: KilobytesValue | None = None

    # CPU time of the collection ("[Times: user= sys= real=]", unified gc,cpu), when logged
    cpu_user_seconds: float | None = None
    cpu_sys_seconds: float | None = None
    cpu_real_seconds: float | None = None

    # Survivor space after the collection, from -XX:+PrintHeapAtGC ("from space NK, P% used")
    survivor_capacity_kb: KilobytesValue | None = None
    survivor_used_percentage: PercentageValue | None = None

    # Provenance
    source_file: str | None = None
    line_number: int | None = None  # 1-based, first line of the record
    segment: int = 1  # JVM run within the input (1-based); see segments.py

    @property
    def pause_start(self) -> datetime:
        """When the pause began, whichever end of the pause the log stamped."""
        if self.stamp_at_pause_end:
            return self.timestamp - timedelta(seconds=self.pause_time_seconds)
        return self.timestamp

    @property
    def pause_end(self) -> datetime:
        """When the pause finished, whichever end of the pause the log stamped."""
        if self.stamp_at_pause_end:
            return self.timestamp
        return self.timestamp + timedelta(seconds=self.pause_time_seconds)


class DiagnosticThresholds(BaseModel):
    """Configurable thresholds for diagnostic warnings."""

    heap_critical_percentage: float = 95.0
    heap_warning_percentage: float = 80.0
    heap_minimum_headroom_percentage: float = 5.0

    full_gc_critical_per_hour: float = 10.0
    full_gc_warning_per_hour: float = 1.0

    gc_overhead_critical_percentage: float = 20.0
    gc_overhead_warning_percentage: float = 10.0

    # P99 pause (of the kind of pause with the worst P99). Defaults suit a request-serving
    # JVM (Tomcat behind a proxy); ``for_workload("batch")`` gives the throughput-first set.
    pause_critical_seconds: float = 5.0
    pause_warning_seconds: float = 1.0
    # Any single stop this long, GC pause or other safepoint
    longest_pause_critical_seconds: float = 30.0
    longest_pause_warning_seconds: float = 5.0

    # Second half below this share of the first half, with a monotonic trend
    reclamation_decline_threshold: float = 0.7
    full_gc_acceleration_threshold: float = 0.7
    # Half-versus-half comparisons of Full GCs need at least this many heap-pressure Full GCs
    min_full_gcs_for_trend: int = 6
    # Mann-Kendall significance for every trend test (floors, Full GC intervals, reclaim)
    trend_p_value: float = 0.05
    # A significant floor trend only matters when it moves the floor this far over the span
    trend_min_growth_capacity_percentage: float = 5.0

    # P1.4: per-hour rates and rate-based warnings need at least this much log
    min_rate_window_hours: float = 1.0
    # P1.7: this many heap-pressure Full GCs inside the window is a thrashing streak
    full_gc_streak_count: int = 3
    full_gc_streak_window_seconds: float = 300.0
    # P1.1: the old-gen floor trend needs this many floors spanning this long
    min_floor_count: int = 3
    min_floor_span_hours: float = 1.0
    # Share of wall-clock time paused inside the worst 5-minute stretch
    pause_share_critical_percentage: float = 50.0
    pause_share_warning_percentage: float = 25.0
    # A heap-pressure Full GC that frees less than this share of the heap achieved little
    ineffective_full_gc_reclaim_percentage: float = 20.0
    # JVM start-up (class loading, cache fill) is left out of growth figures
    warmup_seconds: float = 600.0
    # A floor this many times the median of the floors before it, and higher by at least
    # this share of capacity, is a step change in the live set
    floor_step_factor: float = 2.0
    # Young collections leaving the survivor space this full count as overflowing it
    survivor_full_percentage: float = 99.0
    survivor_overflow_min_count: int = 3
    # Concurrent collector work above this share of the window is near-continuous marking
    concurrent_share_warning_percentage: float = 25.0
    floor_step_min_capacity_percentage: float = 10.0
    # G1: humongous regions holding this share of the max heap, or humongous allocation
    # making up this share of all allocation, is a humongous-object problem
    humongous_heap_share_warning_percentage: float = 10.0
    humongous_allocation_share_warning_percentage: float = 20.0

    @classmethod
    def for_workload(cls, workload: str) -> DiagnosticThresholds:
        """Thresholds for a "server" (request-serving, the default) or "batch" workload.

        "batch" restores the limits used before v6: P99 over 5 s / 10 s, and a single pause
        only matters from 60 s (critical from 300 s).
        """
        if workload == "server":
            return cls()
        if workload == "batch":
            return cls(
                pause_warning_seconds=5.0,
                pause_critical_seconds=10.0,
                longest_pause_warning_seconds=60.0,
                longest_pause_critical_seconds=300.0,
            )
        raise ValueError(f"--workload must be 'server' or 'batch', not {workload!r}")


type LeakVerdictName = Literal["growing", "step_change", "full", "none", "not_assessed"]


class LeakVerdict(BaseModel):
    """What the log shows about the live set, with the evidence for it.

    growing: floors after cleaning collections rise (trend test passed, growth is material).
    step_change: the live set jumped between two collections and stayed up.
    full: live data fills the space and no growth trend explains it (or none could be tested).
    none: floors (or, without floors, the lowest heap after GC) show no material growth.
    not_assessed: the log has nothing to measure the live set with.
    """

    verdict: LeakVerdictName = "not_assessed"
    evidence: list[str] = Field(default_factory=list)
    # "floors" (after collections that clean the old generation) or "upper bound" (lowest
    # heap after any GC: includes uncollected garbage, so it can only rule growth out)
    basis: Literal["floors", "upper bound", ""] = ""


class MetaspaceAnalysis(BaseModel):
    """Metaspace usage statistics and diagnostics."""

    metaspace_events_count: int
    average_metaspace_used_percentage: float
    peak_metaspace_used_percentage: float
    metaspace_growth_kb: int
    metaspace_growing: bool
    metadata_full_gc_count: int = 0
    metaspace_warnings: list[str] = Field(default_factory=list)
    # Used sizes as logged. The percentages above are of -XX:MaxMetaspaceSize and are only
    # meaningful when limit_known: the bracketed figure in the log is reserved/committed
    # space, not a limit.
    first_used_kb: int = 0
    peak_used_kb: int = 0
    last_used_kb: int = 0
    max_metaspace_kb: int | None = None
    limit_known: bool = False
    # False when the log has no samples after warm-up, so growth could not be measured
    growth_measured: bool = False


class JVMHeapConfig(BaseModel):
    """JVM heap and GC tuning configuration extracted from CommandLine flags."""

    # Heap sizing
    initial_heap_size_bytes: int | None = None  # -Xms or -XX:InitialHeapSize
    max_heap_size_bytes: int | None = None  # -Xmx or -XX:MaxHeapSize
    new_size_bytes: int | None = None  # -Xmn or -XX:NewSize
    max_new_size_bytes: int | None = None  # -XX:MaxNewSize
    old_size_bytes: int | None = None  # -XX:OldSize
    max_ram_bytes: int | None = None  # -XX:MaxRAM
    initial_ram_percentage: int | None = None  # -XX:InitialRAMPercentage
    min_ram_percentage: int | None = None  # -XX:MinRAMPercentage
    max_ram_percentage: int | None = None  # -XX:MaxRAMPercentage
    max_ram_fraction: int | None = None  # -XX:MaxRAMFraction (legacy)
    soft_max_heap_size_bytes: int | None = None  # -XX:SoftMaxHeapSize (ZGC)
    min_heap_size_bytes: int | None = None  # JDK 17+ gc,init "Heap Min Capacity"
    always_pre_touch: bool | None = None  # -XX:+AlwaysPreTouch
    heap_dump_on_out_of_memory_error: bool | None = None  # -XX:+HeapDumpOnOutOfMemoryError
    thread_stack_size_kb: int | None = None  # -XX:ThreadStackSize
    new_ratio: int | None = None  # -XX:NewRatio
    survivor_ratio: int | None = None  # -XX:SurvivorRatio
    initial_survivor_ratio: int | None = None  # -XX:InitialSurvivorRatio
    target_survivor_ratio: int | None = None  # -XX:TargetSurvivorRatio
    max_tenuring_threshold: int | None = None  # -XX:MaxTenuringThreshold
    max_heap_free_ratio: int | None = None  # -XX:MaxHeapFreeRatio
    min_heap_free_ratio: int | None = None  # -XX:MinHeapFreeRatio

    # Metaspace
    metaspace_size_bytes: int | None = None  # -XX:MetaspaceSize
    max_metaspace_size_bytes: int | None = None  # -XX:MaxMetaspaceSize
    max_direct_memory_size_bytes: int | None = None  # -XX:MaxDirectMemorySize

    # GC Threading
    parallel_gc_threads: int | None = None  # -XX:ParallelGCThreads
    conc_gc_threads: int | None = None  # -XX:ConcGCThreads

    # GC Behavior Tuning
    max_gc_pause_millis: int | None = None  # -XX:MaxGCPauseMillis
    gc_time_ratio: int | None = None  # -XX:GCTimeRatio
    adaptive_size_policy_weight: int | None = None  # -XX:AdaptiveSizePolicyWeight
    use_adaptive_size_policy: bool | None = None  # -XX:+UseAdaptiveSizePolicy
    use_adaptive_size_policy_footprint_goal: bool | None = (
        None  # -XX:+UseAdaptiveSizePolicyFootprintGoal
    )

    # G1-specific
    g1_heap_region_size_bytes: int | None = None  # -XX:G1HeapRegionSize
    initiating_heap_occupancy_percent: int | None = None  # -XX:InitiatingHeapOccupancyPercent
    g1_reserve_percent: int | None = None  # -XX:G1ReservePercent
    g1_new_size_percent: int | None = None  # -XX:G1NewSizePercent
    g1_max_new_size_percent: int | None = None  # -XX:G1MaxNewSizePercent
    g1_mixed_gc_count_target: int | None = None  # -XX:G1MixedGCCountTarget
    g1_heap_waste_percent: int | None = None  # -XX:G1HeapWastePercent
    g1_mixed_gc_live_threshold_percent: int | None = None  # -XX:G1MixedGCLiveThresholdPercent
    g1_rset_updating_pause_time_percent: int | None = None  # -XX:G1RSetUpdatingPauseTimePercent
    g1_old_cset_region_threshold_percent: int | None = None  # -XX:G1OldCSetRegionThresholdPercent

    # CMS-specific
    cms_initiating_occupancy_fraction: int | None = None  # -XX:CMSInitiatingOccupancyFraction
    use_cms_initiating_occupancy_only: bool | None = None  # -XX:+UseCMSInitiatingOccupancyOnly
    cms_full_gcs_before_compaction: int | None = None  # -XX:CMSFullGCsBeforeCompaction
    cms_wait_duration: int | None = None  # -XX:CMSWaitDuration

    def format_size(self, size_bytes: int | None) -> str:
        """Format bytes to human-readable size."""
        if size_bytes is None:
            return "Not set"

        # Convert to appropriate unit
        if size_bytes >= 1024**3:  # GB
            return f"{size_bytes / (1024**3):.1f}G"
        elif size_bytes >= 1024**2:  # MB
            return f"{size_bytes / (1024**2):.1f}M"
        elif size_bytes >= 1024:  # KB
            return f"{size_bytes / 1024:.1f}K"
        return f"{size_bytes}B"


class G1Metrics(BaseModel):
    """G1 GC-specific diagnostic metrics."""

    mixed_gc_count: int
    mixed_gc_frequency_per_hour: float | None
    average_mixed_gc_pause_seconds: float
    humongous_allocation_count: int
    evacuation_failure_count: int
    to_space_exhausted_count: int
    concurrent_marking_cycles: int = 0
    # Pauses that started marking, and how many of those name a humongous allocation as cause
    concurrent_start_count: int = 0
    humongous_concurrent_start_count: int = 0
    # Old-generation occupancy (old + humongous) right after the pauses that start marking,
    # as % of max heap: where G1's marking threshold sits in practice
    median_marking_start_pct: float | None = None
    marking_cycles_per_hour: float | None = None
    mixed_per_marking_cycle: float | None = None
    # Humongous regions (None when the log has no region counts)
    peak_humongous_kb: int | None = None
    peak_humongous_pct: float | None = None  # of max (or committed) heap
    # Median humongous occupancy before a pause: what humongous objects normally hold. The
    # warning is judged on this, not on the peak, which a single burst can set.
    typical_humongous_kb: int | None = None
    typical_humongous_pct: float | None = None
    humongous_allocation_mb_sec: float | None = None
    humongous_allocation_share_pct: float | None = None  # of all allocation
    mmu_violation_count: int = 0
    g1_warnings: list[str] = Field(default_factory=list)


class CMSMetrics(BaseModel):
    """CMS GC-specific diagnostic metrics."""

    model_config = ConfigDict(frozen=True)

    concurrent_cycles: int = 0  # = Initial Mark pauses
    cms_cycle_frequency_per_hour: float | None = None
    concurrent_mode_failures: int = 0
    promotion_failures: int = 0
    average_initial_mark_pause_seconds: float = 0.0
    average_remark_pause_seconds: float = 0.0


class CandidateCoverage(BaseModel):
    """GC-event-like lines found in the log vs. the ones the parser turned into events."""

    model_config = ConfigDict(frozen=True)

    candidate_lines: int
    parsed_candidate_lines: int
    unparsed_samples: list[str] = Field(default_factory=list)
    total_lines: int = 0
    # "L2172: <text>" when the log stops in the middle of a GC record (not counted as unparsed)
    truncated_final_record: str | None = None
    # Physical lines folded into a multi-line record (tenuring tables, interleaved phases)
    continuation_lines: int = 0

    @property
    def unparsed_candidate_lines(self) -> int:
        """Candidate lines that produced no event."""
        return self.candidate_lines - self.parsed_candidate_lines

    @property
    def unparsed_percentage(self) -> float:
        """Unparsed candidates as a percentage of all candidates."""
        if self.candidate_lines == 0:
            return 0.0
        return self.unparsed_candidate_lines / self.candidate_lines * 100.0


class FileCoverage(BaseModel):
    """Parsing coverage for one input file."""

    path: str
    gc_type: str
    coverage: CandidateCoverage
    events: int
    events_without_heap_data: int


class PauseStats(BaseModel):
    """Pause-time distribution for one GC kind (or all kinds)."""

    count: int = 0
    total: float = 0.0
    average: float = 0.0
    median: float = 0.0
    p95: float = 0.0
    p99: float = 0.0
    maximum: float = 0.0


class PauseShareWindow(BaseModel):
    """The stretch of the given length with the most time spent paused."""

    window_seconds: float
    paused_seconds: float
    share_percentage: float
    window_start: datetime
    wall_clock: bool = True
    uptime_seconds: float | None = None  # of window_start, when the log has uptime


class SideRecord(BaseModel):
    """A log line that is not a GC pause but matters for diagnosis."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["concurrent", "safepoint", "mmu"]
    line_number: int  # 1-based
    seconds: float  # concurrent work duration, or total time the application was stopped
    stopping_seconds: float | None = None  # safepoint: time to bring the threads to a stop
    label: str = ""  # concurrent: what the duration covers
    when: str = ""  # time as written in the log
    # safepoint (JDK 13+): the VM operation, e.g. "G1CollectForAllocation", "ThreadDump"
    operation: str = ""
    # concurrent: "mark", "sweep" (CMS: the old generation has just been cleaned) or "cycle"
    phase: str = ""
    # When the line was written (the end of what it reports), for placing it among pauses
    uptime_seconds: float | None = None
    timestamp: datetime | None = None
    source_file: str | None = None


class ConcurrentStats(BaseModel):
    """Concurrent collector work (runs alongside the application; not pause time)."""

    label: str
    cycles: int
    total_seconds: float
    share_percentage: float | None  # of the window; None for a window without elapsed time
    average_seconds: float
    longest_seconds: float
    # Time from the first to the last cycle; None when the lines carry no time
    first_when: str = ""
    last_when: str = ""
    span_seconds: float | None = None


class SafepointStats(BaseModel):
    """Application-stopped time from safepoint logging (includes non-GC safepoints)."""

    count: int
    total_stopped_seconds: float
    longest_stopped_seconds: float
    longest_stopped_when: str
    # Safepoints where bringing the threads to a stop took a second or more
    slow_to_stop_count: int = 0
    longest_stopping_seconds: float = 0.0
    longest_stopping_when: str = ""
    # Stops no GC pause overlaps (thread dumps, deoptimization, biased-lock revocation, ...).
    # None when the stops could not be placed in time against the pauses.
    non_gc_count: int | None = None
    non_gc_total_seconds: float = 0.0
    longest_non_gc_seconds: float = 0.0
    longest_non_gc_when: str = ""
    longest_non_gc_operation: str = ""
    longest_non_gc_stopping_seconds: float | None = None
    non_gc_over_warning_count: int = 0


class CpuStats(BaseModel):
    """CPU time of pauses. Only pauses with real >= 0.1 s are judged (log resolution is 10 ms)."""

    pauses_with_cpu_times: int
    judged_pauses: int
    # sys > 20% of user: time went to the kernel (memory management), not to collecting
    high_sys_count: int = 0
    worst_high_sys: str = ""  # "user=2.00 sys=5.00 real=1.00 at <time>"
    # real > 1.5 x (user + sys): the collector was waiting, not running
    off_cpu_count: int = 0
    worst_off_cpu: str = ""
    # Median (user + sys) / real per pause kind over the judged pauses: how many threads'
    # worth of CPU the collector actually used
    parallelism_by_kind: dict[str, float] = Field(default_factory=dict)


class JVMEnvironment(BaseModel):
    """JVM and host facts printed at the top of the log."""

    jvm_version: str | None = None
    cpus_total: int | None = None
    cpus_available: int | None = None
    physical_memory_kb: int | None = None
    free_memory_kb: int | None = None
    swap_total_kb: int | None = None
    swap_free_kb: int | None = None
    large_pages: str | None = None
    pre_touch: str | None = None


class HealthWarning(BaseModel):
    """One health warning. ``code`` identifies the condition; ``text`` is for people."""

    model_config = ConfigDict(frozen=True)

    code: str
    level: Literal["CRITICAL", "WARNING"]
    text: str

    @property
    def line(self) -> str:
        """'CRITICAL: ...' / 'WARNING: ...', as listed in ``GCSummary.warnings``."""
        return f"{self.level}: {self.text}"


class SurvivorOverflow(BaseModel):
    """Young collections that left the survivor space full and promoted the excess."""

    count: int
    young_gc_count: int  # young collections that logged survivor occupancy
    first_when: str
    last_when: str
    survivor_capacity_kb: int
    promoted_kb: int  # old-generation growth across those collections


class Finding(BaseModel):
    """One ranked conclusion of the report: what, when, on what evidence, and what to do."""

    severity: Literal["critical", "warning", "info"]
    title: str
    when: str = ""
    evidence: list[str] = Field(default_factory=list)
    # high: read straight off the log; medium: an interpretation of it; low: thin data
    confidence: Literal["high", "medium", "low"] = "high"
    action: str = ""
    source: str = ""  # documentation the action restates
    # "cause": what went wrong first; "symptom": what followed from it; "": unrelated
    role: Literal["cause", "symptom", ""] = ""


class TimelineBucket(BaseModel):
    """One slice of the analysis window: what GC did in it."""

    start: datetime
    wall_clock: bool = True
    uptime_seconds: float | None = None
    length_seconds: float
    pause_count: int = 0
    paused_seconds: float = 0.0
    paused_percentage: float = 0.0
    longest_pause_seconds: float = 0.0
    full_gc_count: int = 0
    # After the last collecting pause (Young/Mixed/Full) in the slice; None when there was none
    heap_after_kb: int | None = None
    heap_after_percentage: float | None = None


class FullGCCause(BaseModel):
    """Full GC count for one cause."""

    cause: str
    category: FullGCCategory
    count: int
    total_pause_seconds: float
    max_pause_seconds: float


class FloorPoint(BaseModel):
    """Occupancy right after a collection that clears the old generation (a 'floor')."""

    timestamp: datetime
    uptime_seconds: float | None
    wall_clock: bool
    value_kb: int
    pct_of_capacity: float | None
    source: str  # "Full GC (Allocation Failure)", "end of mixed cycle", "Remark"
    # Taken during JVM start-up (class loading, cache fill): listed, but not part of the trend
    warmup: bool = False


class FloorStep(BaseModel):
    """A jump between two consecutive floors: sudden retention, not gradual growth."""

    before: FloorPoint
    after: FloorPoint


class FloorTrend(BaseModel):
    """Trend of post-collection floors: the leak signal.

    The slope is the Theil-Sen estimate (median of all pairwise slopes), which a few outlying
    floors cannot drag; whether a trend exists is the Mann-Kendall test; whether it matters
    is the growth over the span as a share of capacity.
    """

    assessed: bool
    reason: str | None = None  # why not assessed
    metric: Literal["old", "heap"] = "old"
    capacity_kb: int | None = None  # denominator for pct_of_capacity
    capacity_source: str | None = None
    floors: list[FloorPoint] = Field(default_factory=list)
    span_hours: float = 0.0
    slope_mb_per_hour: float | None = None
    slope_pct_per_hour: float | None = None
    # Mann-Kendall two-sided p-value of "the floors have a monotonic trend"
    p_value: float | None = None
    # slope x span, as MB and as % of capacity
    growth_mb: float | None = None
    growth_pct_of_capacity: float | None = None
    # "growing": significant and material; "stable": no material growth; "unclear": the
    # floors moved materially but not consistently
    direction: Literal["growing", "stable", "unclear"] | None = None
    # 90% confidence interval of the slope (Sen), and the hours until the floor reaches
    # capacity at those slopes if growth stays linear (None = not within reach)
    slope_low_mb_per_hour: float | None = None
    slope_high_mb_per_hour: float | None = None
    hours_to_capacity_soonest: float | None = None
    hours_to_capacity_latest: float | None = None
    # Floors the statistics were computed on (an even sample when there are very many)
    trend_sample_size: int = 0
    # True when the window spans several JVM runs and only the latest run's floors are used
    latest_run_only: bool = False
    first_mb: float | None = None
    last_mb: float | None = None
    step_change: FloorStep | None = None

    @property
    def trend_floors(self) -> list[FloorPoint]:
        """Floors the trend is computed from (start-up floors left out)."""
        return [f for f in self.floors if not f.warmup]


class LiveSetBound(BaseModel):
    """Lowest heap after GC in each slice of the window: an upper bound on the live set.

    Used when the window has too few floors. It still contains old-generation garbage that
    no collection has removed yet, so a flat bound rules growth out, while a rising bound
    proves nothing.
    """

    assessed: bool = False
    slices: int = 0
    span_hours: float = 0.0
    first_kb: int = 0
    last_kb: int = 0
    lowest_kb: int = 0
    highest_kb: int = 0
    growth_pct_of_capacity: float | None = None
    p_value: float | None = None
    direction: Literal["flat", "rising", "unclear"] | None = None


class HeapStats(BaseModel):
    """Heap occupancy before/after GC against the max heap (P1.3)."""

    events_with_heap_data: int = 0
    max_heap_kb: int | None = None
    # e.g. "-Xmx (CommandLine flags)", "--max-heap", "JVM startup log", or
    # "committed heap (max heap unknown)" when no max is known
    max_heap_source: str = "committed heap (max heap unknown)"
    max_heap_known: bool = False
    peak_before_gc_kb: int = 0
    peak_after_gc_kb: int = 0
    avg_after_gc_kb: float = 0.0
    peak_before_gc_pct: float = 0.0
    peak_after_gc_pct: float = 0.0
    avg_after_gc_pct: float = 0.0
    headroom_pct: float = 100.0  # 100 - peak_after_gc_pct
    # "After GC" figures only use pauses that collect (Young, Mixed, Full)
    collecting_events_with_heap_data: int = 0
    # Occupancy above the stated max heap: the max heap value is wrong for this log
    exceeds_max_heap: bool = False
    # Committed heap as logged with each pause: growth means -Xms is below -Xmx
    first_committed_kb: int = 0
    last_committed_kb: int = 0
    min_committed_kb: int = 0
    max_committed_kb: int = 0


class PeriodStatistics(BaseModel):
    """Statistics for a time period."""

    average_old_gen_percentage: float | None
    full_gc_count: int


class SegmentInfo(BaseModel):
    """One JVM run (segment) found in the input."""

    index: int
    first_timestamp: datetime
    last_timestamp: datetime
    wall_clock: bool
    first_uptime_seconds: float | None
    last_uptime_seconds: float | None
    events: int
    files: list[str]


class GCSummary(BaseModel):
    """Complete GC analysis summary for one analysis window."""

    # Window
    runtime_seconds: float
    runtime_hours: float
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    wall_clock: bool = True
    # P1.4: per-hour rates are only computed when the window is long enough
    rates_reliable: bool = False

    # Counts
    total_event_count: int
    counts_by_kind: dict[str, int] = Field(default_factory=dict)
    young_gc_count: int = 0
    mixed_gc_count: int = 0
    full_gc_count: int = 0
    initial_mark_count: int = 0
    remark_gc_count: int = 0
    cleanup_gc_count: int = 0
    promotion_failure_count: int = 0  # any generational collector
    heap_full_gc_count: int = 0  # Full GCs not explained by System.gc()/metadata
    explicit_full_gc_count: int = 0
    metadata_full_gc_count: int = 0
    full_gc_causes: list[FullGCCause] = Field(default_factory=list)
    causes_by_kind: dict[str, dict[str, int]] = Field(default_factory=dict)

    # Frequency (None when rates_reliable is False)
    young_gc_per_hour: float | None = None
    full_gc_per_hour: float | None = None  # heap-pressure Full GCs only
    avg_full_gc_interval_min: float | None = None
    min_full_gc_interval_min: float | None = None
    time_to_first_full_gc_hours: float | None = None
    # True: measured from JVM start (uptime); False: from the first pause in the window
    time_to_first_full_gc_from_jvm_start: bool = False
    full_gc_accelerating: bool = False
    # Most heap-pressure Full GCs with the last starting within the streak window of the
    # first one finishing
    max_full_gc_streak: int = 0

    # Overhead (pause time inside the window / window length)
    total_gc_time_sec: float = 0.0
    gc_overhead_pct: float = 0.0
    throughput_pct: float = 100.0
    # False when the window is a single pause: there is no elapsed time to divide by
    overhead_measured: bool = True
    worst_pause_shares: list[PauseShareWindow] = Field(default_factory=list)
    # The window cut into equal slices, so the reader can see when behaviour changed
    timeline: list[TimelineBucket] = Field(default_factory=list)
    timeline_bucket_seconds: float = 0.0

    # Pauses
    overall_pauses: PauseStats = Field(default_factory=PauseStats)
    pauses_by_kind: dict[str, PauseStats] = Field(default_factory=dict)
    # The kind of pause with the highest P99 among kinds with at least 100 pauses (a P99 of
    # fewer is just the maximum); None when no kind has that many, and the all-pauses P99 is
    # used. Thousands of millisecond-long Cleanup pauses otherwise hide a slow kind.
    worst_p99_kind: str | None = None
    worst_p99_seconds: float = 0.0
    worst_p99_count: int = 0
    longest_pause_kind: str = ""
    longest_pause_cause: str = ""
    longest_pause_when: str = ""
    pauses_over_1s: int = 0
    pauses_over_5s: int = 0
    pauses_over_30s: int = 0
    pauses_over_60s: int = 0

    # Heap (P1.3, P1.5)
    heap: HeapStats = Field(default_factory=HeapStats)

    # Old gen. old_pct_basis names the denominator of every old-gen percentage
    peak_old_pct: float | None = None
    avg_old_pct: float | None = None
    old_pct_basis: str = "old generation capacity"
    old_pct_capacity_kb: int | None = None  # fixed denominator (G1 with a known max heap)
    floor_trend: FloorTrend = Field(default_factory=lambda: FloorTrend(assessed=False))

    # Full GC effectiveness (all Full GCs: each is a measurement of the live set)
    full_gc_reducing: int = 0
    full_gc_growing: int = 0
    avg_post_full_gc_pct: float | None = None
    avg_reclaimed_kb: float = 0.0
    reclamation_declining: bool = False
    # Whole-heap reclaim (heap before - heap after) as % of heap before
    avg_full_gc_reclaimed_pct: float | None = None
    # Heap-pressure Full GCs only, in time order
    heap_full_gc_reclaimed_pcts: list[float] = Field(default_factory=list)
    ineffective_full_gc_count: int = 0

    # Allocation (P1.8)
    avg_promotion_kb: float = 0.0
    total_promoted_kb: int = 0
    promotion_rate_mb_sec: float | None = None
    allocation_rate_mb_sec: float | None = None
    allocation_basis: str | None = None  # "young generation" or "whole heap"
    # G1 evacuation failures after JVM start-up (the ones that count against steady state)
    evacuation_failures_after_warmup: int = 0

    period_stats: dict[str, PeriodStatistics] = Field(default_factory=dict)

    leak: LeakVerdict = Field(default_factory=LeakVerdict)
    live_set_bound: LiveSetBound = Field(default_factory=LiveSetBound)
    metaspace_analysis: MetaspaceAnalysis | None = None
    g1_metrics: G1Metrics | None = None
    cms_metrics: CMSMetrics | None = None
    jvm_heap_config: JVMHeapConfig | None = None
    cpu_stats: CpuStats | None = None
    survivor_overflow: SurvivorOverflow | None = None
    # True when young collections logged survivor occupancy (so overflow could be assessed)
    survivor_occupancy_logged: bool = False
    unified_log: bool = False
    has_uptime: bool = True
    is_g1: bool = False
    # JVM runs (segments) in the window; downtime between runs is not part of the window
    jvm_run_count: int = 1
    concurrent_stats: ConcurrentStats | None = None
    safepoint_stats: SafepointStats | None = None
    environment: JVMEnvironment | None = None

    # The limits this summary was judged against (so the report can name them)
    thresholds: DiagnosticThresholds = Field(default_factory=DiagnosticThresholds)

    # Health warnings and data-quality notes, kept apart. ``warnings`` holds the same
    # warnings as ``health_warnings`` as "WARNING: ..."/"CRITICAL: ..." lines.
    health_warnings: list[HealthWarning] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    data_notes: list[str] = Field(default_factory=list)
