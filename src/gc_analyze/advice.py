"""Advice table: what to do about a finding, by collector and JDK release.

Every entry restates what the cited JDK documentation says; nothing here is folklore. When an
entry is changed, re-read its source. Sources were read on 2026-11-15.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import JVMEnvironment

GC_TUNING_17 = "https://docs.oracle.com/en/java/javase/17/gctuning"
GC_TUNING_8 = "https://docs.oracle.com/javase/8/docs/technotes/guides/vm/gctuning"

G1_TUNING = (
    "HotSpot GC Tuning Guide (JDK 17), Garbage-First Garbage Collector Tuning: "
    f"{GC_TUNING_17}/garbage-first-garbage-collector-tuning.html"
)
SELECTING = (
    "HotSpot GC Tuning Guide (JDK 17), Available Collectors - Selecting a Collector: "
    f"{GC_TUNING_17}/available-collectors.html"
)
SIZING = (
    "HotSpot GC Tuning Guide (JDK 17), Factors Affecting Garbage Collection Performance: "
    f"{GC_TUNING_17}/factors-affecting-garbage-collection-performance.html"
)
CONSIDERATIONS_8 = (
    f"HotSpot GC Tuning Guide (Java 8), Other Considerations: {GC_TUNING_8}/considerations.html"
)
PARALLEL_8 = (
    f"HotSpot GC Tuning Guide (Java 8), The Parallel Collector: {GC_TUNING_8}/parallel.html"
)
CMS_8 = (
    "HotSpot GC Tuning Guide (Java 8), Concurrent Mark Sweep (CMS) Collector: "
    f"{GC_TUNING_8}/cms.html"
)
JEP_307 = "JEP 307: Parallel Full GC for G1 (delivered in JDK 10): https://openjdk.org/jeps/307"
JEP_423 = "JEP 423: Region Pinning for G1 (delivered in JDK 22): https://openjdk.org/jeps/423"
JCMD = (
    "jcmd tool reference (JDK 17), GC.heap_dump: "
    "https://docs.oracle.com/en/java/javase/17/docs/specs/man/jcmd.html"
)


@dataclass(frozen=True)
class Advice:
    """What the documentation says to do, and where it says it."""

    text: str
    source: str


ADVICE: dict[str, Advice] = {
    "heap_dump": Advice(
        "Take a heap dump while the heap is in this state: jcmd <pid> GC.heap_dump <file>. It "
        "requests a full GC first and its impact depends on heap size, so expect a pause on a "
        "large heap",
        JCMD,
    ),
    "old_gen_slack": Advice(
        "Keep the old generation large enough to hold all the live data the application uses "
        "at any time, plus 10 to 20% or more of slack",
        SIZING,
    ),
    "survivor_overflow": Advice(
        "If survivor spaces are too small, the copying collection overflows directly into the "
        "old generation, which then fills with objects that would have died young. Survivor "
        "size is set relative to eden with -XX:SurvivorRatio (a lower ratio gives larger "
        "survivors); the young generation itself is bounded by -XX:NewSize and -XX:MaxNewSize",
        SIZING,
    ),
    "g1_full_gc": Advice(
        "A G1 Full GC means objects that cannot be reclaimed were allocated faster than "
        "concurrent marking could finish. The documented options: increase the Java heap; "
        "raise -XX:ConcGCThreads; start marking earlier by raising -XX:G1ReservePercent, or by "
        "setting -XX:-G1UseAdaptiveIHOP with a lower -XX:InitiatingHeapOccupancyPercent; and "
        "reduce humongous allocations",
        G1_TUNING,
    ),
    "g1_full_gc_single_threaded": Advice(
        "On this release a G1 Full GC runs on a single thread, so it is long on a large heap; "
        "the parallel Full GC arrived in JDK 10",
        JEP_307,
    ),
    "g1_evacuation_failure": Advice(
        "An evacuation failure means G1 could not find enough free space to copy live objects "
        "into, and a Full GC typically follows. The documented options are the same as for "
        "Full GCs: increase the Java heap; start marking earlier by raising "
        "-XX:G1ReservePercent, or by setting -XX:-G1UseAdaptiveIHOP with a lower "
        "-XX:InitiatingHeapOccupancyPercent; or raise -XX:ConcGCThreads",
        G1_TUNING,
    ),
    "g1_humongous": Advice(
        "Objects of half a region or more are humongous: they are allocated straight into the "
        "old generation as whole contiguous regions and are normally reclaimed only after "
        "marking or by a Full GC. Increase -XX:G1HeapRegionSize so fewer objects are "
        "humongous (a power of 2 from 1 to 32 MB), or increase the heap",
        G1_TUNING,
    ),
    "g1_remark": Advice(
        "The Remark pause finalizes marking and performs global reference processing and class "
        "unloading. Look at the Reference Processing phase in the pause breakdown. G1 starts "
        "one reference-processing thread per -XX:ReferencesPerThread references, up to "
        "-XX:ParallelGCThreads; setting -XX:ReferencesPerThread=0 uses all threads. Check that "
        "parallel reference processing has not been turned off with -XX:-ParallelRefProcEnabled "
        "(these defaults are as documented for JDK 17; confirm them for an older release)",
        G1_TUNING,
    ),
    "g1_young_pause": Advice(
        "If young collections take too long in the Evacuate Collection Set phase, the "
        "documented options are to lower -XX:G1NewSizePercent and -XX:G1MaxNewSizePercent, "
        "which limit the young generation and so the number of objects processed in a pause",
        G1_TUNING,
    ),
    "high_sys_time": Advice(
        "When system time is relatively high, the environment is most often the cause. The "
        "documented remedies: set -Xms and -Xmx to the same value and pre-touch memory with "
        "-XX:+AlwaysPreTouch so the operating system hands over memory at start-up instead of "
        "during pauses; and on Linux consider disabling Transparent Huge Pages, whose "
        "coalescing of small pages tends to stall processes",
        G1_TUNING,
    ),
    "off_cpu": Advice(
        "Real time far above user plus system time may mean the JVM did not get enough CPU "
        "time on an overloaded machine. Writing the GC log can also stall when another task "
        "uses up the disk's I/O; a separate disk or a memory-backed file system for the log "
        "avoids that",
        G1_TUNING,
    ),
    "explicit_gc_g1": Advice(
        "A Full GC with a cause other than Allocation Failure is requested by the application "
        "or an external tool. If the cause is System.gc() and the code cannot be changed, "
        "-XX:+ExplicitGCInvokesConcurrent mitigates it, or -XX:+DisableExplicitGC makes the "
        "JVM ignore the calls. Collections forced by external tools can only be removed by "
        "not requesting them",
        G1_TUNING,
    ),
    "explicit_gc": Advice(
        "System.gc() can force a major collection when a minor one would do and should "
        "generally be avoided. -XX:+DisableExplicitGC makes the JVM ignore the calls, which "
        "also shows how much they cost",
        CONSIDERATIONS_8,
    ),
    "rmi_dgc": Advice(
        "Evenly spaced explicit Full GCs are the signature of RMI distributed garbage "
        "collection, which forces full collections periodically. The interval is set in "
        "milliseconds with -Dsun.rmi.dgc.client.gcInterval and -Dsun.rmi.dgc.server.gcInterval "
        "(a longer interval can delay reclaiming remote objects)",
        CONSIDERATIONS_8,
    ),
    "metaspace_threshold": Advice(
        "A collection is induced each time committed class metadata reaches a high-water mark "
        "that starts at -XX:MetaspaceSize (platform default 12 to about 20 MB). Set a higher "
        "-XX:MetaspaceSize to avoid these early collections",
        CONSIDERATIONS_8,
    ),
    "metaspace_limit": Advice(
        "Class metadata lives in native memory, unlimited by default; -XX:MaxMetaspaceSize "
        "caps it. Metadata is only freed when its classes are unloaded, so sustained growth "
        "means classes keep being loaded and not unloaded",
        CONSIDERATIONS_8,
    ),
    "selecting_collector": Advice(
        "The parallel collector is the documented choice when peak throughput comes first and "
        "pauses of one second or longer are acceptable. When response time matters more than "
        "throughput, select G1 (-XX:+UseG1GC); when it is a high priority, a fully concurrent "
        "collector (ZGC), whose pause times do not depend on heap size",
        SELECTING,
    ),
    "parallel_overhead_limit": Advice(
        "The parallel collector only gives up with an OutOfMemoryError when more than 98% of "
        "the time goes to GC and less than 2% of the heap is recovered, so a JVM recovering "
        "slightly more keeps running in this state instead of failing",
        PARALLEL_8,
    ),
    "cms_concurrent_mode_failure": Advice(
        "A concurrent mode failure means CMS could not finish before the tenured generation "
        "filled up (or free space was too fragmented), so the collection was completed with "
        "the application stopped. Start cycles earlier with a lower "
        "-XX:CMSInitiatingOccupancyFraction (default about 92%), and allow about 20% more "
        "tenured space for floating garbage",
        CMS_8,
    ),
    "gclocker": Advice(
        "A GCLocker Initiated GC is a collection that had to wait for threads inside JNI "
        "critical regions. From JDK 22, G1 pins the regions involved and no longer disables "
        "garbage collection during them",
        JEP_423,
    ),
}

_VERSION_LEGACY = re.compile(r"^1\.(\d+)\.")
_VERSION_MODERN = re.compile(r"^(\d+)(?:[.+\-]|$)")


def jdk_major(environment: JVMEnvironment | None, unified_log: bool) -> int | None:
    """JDK feature release ("1.8.0_202" -> 8, "17.0.9+9" -> 17).

    Without a version in the log, a Java 8 style log is taken as 8; a unified log is JDK 9 or
    later with the exact release unknown (None).
    """
    version = environment.jvm_version if environment else None
    if version:
        if match := _VERSION_LEGACY.match(version):
            return int(match.group(1))
        if match := _VERSION_MODERN.match(version):
            return int(match.group(1))
    return None if unified_log else 8
