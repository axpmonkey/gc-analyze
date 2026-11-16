# gc-analyze

`gc-analyze` is a command-line utility that parses JVM garbage-collection (GC) logs and produces an
operations-oriented report: what paused the JVM, for how long and why, whether the live set is
growing, and whether the log was fully understood.

## What it does

Given one or more GC log files, the tool:

- Detects the log format (Java 8 `-XX:+PrintGC*` or JDK 9+ unified `-Xlog:gc*`) and the collector.
- Parses every stop-the-world pause, including records spread over several lines, and normalizes it
  into one event model with its **cause** (`Allocation Failure`, `System.gc()`, ...).
- Reports **parsing coverage**: GC lines found, parsed, folded into multi-line records, and up to five
  samples of lines it did not understand. A run that misses more than 1% of GC lines says so at the
  top of the report and exits non-zero.
- Splits the input into JVM runs when the JVM restarted, and orders rotated files by time.
- Computes pause statistics, heap occupancy against the max heap, Full GC causes, and the
  **old-gen floor trend** (the leak signal), then prints a terminal report, optionally a Markdown
  report or a ~5 KB case-file brief, and optionally one JSON line per pause for timelines.

### Supported GC log formats

| Collector | Java 8 (`-XX:+PrintGC`, `-XX:+PrintGCDetails`) | JDK 9+ unified (`-Xlog:gc*`) |
|---|---|---|
| G1 | yes (incl. `PrintAdaptiveSizePolicy`, to-space exhausted) | yes |
| Parallel | yes (`PSYoungGen` / `ParOldGen` / `PSOldGen`) | yes |
| CMS | yes (ParNew + CMS, promotion failed, concurrent mode failure) | yes |
| Serial | yes (`DefNew` / `Tenured`) | yes |
| ParNew + Serial Old | yes | — |
| ZGC, Shenandoah, Epsilon | rejected with a clear message | rejected with a clear message |

Time stamps: datestamps and/or uptime (`-XX:+PrintGCDateStamps`, `-XX:+PrintGCTimeStamps`); any
unified decorator set (`time`, `utctime`, `uptime`, `uptimemillis`, `timemillis`, `uptimenanos`,
`timenanos`, `pid`, `tid`, padded levels and tags). Logs with uptime only are analyzed on uptime;
`--jvm-start` turns uptime into wall-clock time. Multi-line records handled: tenuring-distribution
tables, interleaved CMS/G1 concurrent phases, `G1Ergonomics` lines and `PrintReferenceGC` output.

## Quick start

```bash
uv run gc-analyze analyze path/to/gc.log
```

## Installation

Python **3.15 only** is supported (`>=3.15,<3.16`). Use `uv` for all environment and dependency management.

### Install uv

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh
```

```powershell
# Windows (PowerShell)
irm https://astral.sh/uv/install.ps1 | iex
```

### Setup

```bash
git clone <repository-url>
cd gc-analyze
uv python install 3.15
uv sync --frozen
```

## Usage

```bash
uv run gc-analyze analyze [OPTIONS] LOG_FILE [LOG_FILE ...]
```

| Option | Meaning |
|---|---|
| `--output`, `-o FILE` | Also write the report as Markdown |
| `--brief` | Case-file summary (≤ ~5 KB Markdown): to `--output`, or to stdout without it |
| `--export-events FILE` | One JSON line per pause in the shared `events.jsonl` format (needs wall-clock time) |
| `--host NAME` | Host name written into exported events |
| `--start`, `--end TIME` | Analyze only this window (ISO 8601; without an offset the log's offset is used). With both, the same window 24 h earlier is shown for comparison when the log covers it |
| `--segment latest\|all\|N` | Which JVM run to analyze when the input spans restarts (default `latest`) |
| `--jvm-start TIME` | JVM start time with offset, for logs that only have uptime |
| `--max-heap SIZE` | Max heap (e.g. `4g`) when the log doesn't state it |
| `--min-rate-window MIN` | Minutes of log needed before per-hour rates are shown (default `60`) |
| `--full-gc-streak N` | Back-to-back heap-pressure Full GCs (the last starting within 5 minutes of the first one ending) that count as thrashing (default `3`) |
| `--heap-warning`, `--heap-critical PCT` | Thresholds for occupancy after a collection that cleans the old generation (default `80` / `95`) |
| `--workload server\|batch` | Pause limits to judge by (default `server`, see below) |
| `--verbose`, `-v` | Per-file parsing details |
| `--profile`, `--profile-output FILE` | Profiling statistics |

Examples:

```bash
# rotated files of one JVM, in any order
uv run gc-analyze analyze gc.log.0 gc.log.1 gc.log.2.current

# the incident window, compared with the same window yesterday
uv run gc-analyze analyze gc.log --start 2026-11-10T14:00 --end 2026-11-10T14:30

# a brief for the case file, and pauses for the shared timeline
uv run gc-analyze analyze gc.log --brief -o gc-brief.md --export-events gc.events.jsonl --host host-03
```

Exit codes come from the findings the report lists: `0` no warning or critical finding, `1` a
warning finding or an incomplete parse (> 1% of GC lines not understood), `2` a critical finding.
Informational findings do not change the exit code. The report's Status line uses the same rule.

Pause limits (`--workload`):

| | `server` (default: request-serving JVM, e.g. Tomcat) | `batch` (throughput first; the limits before 6.0.0) |
|---|---|---|
| Any single stop (GC pause or other safepoint) | ≥ 5 s warning, ≥ 30 s critical | ≥ 60 s warning, ≥ 300 s critical |
| P99 pause (needs ≥ 100 pauses) | > 1 s warning, > 5 s critical | > 5 s warning, > 10 s critical |

## How the numbers are defined

- **Pauses**: every stop-the-world pause: Young, Mixed (G1), Full, Initial Mark and Remark (CMS),
  Remark and Cleanup (G1). G1 `Prepare Mixed` and `Concurrent Start` pauses are young pauses. A young
  collection that collects the old generation in the same pause (CMS/Serial promotion failure or
  concurrent mode failure) counts as a Full GC with the failure flagged.
- **Full GC causes**: each Full GC is *heap pressure*, *explicit* or *metaspace*. Explicit means
  requested by code, tooling or a timer rather than by the Java heap: `System.gc()`, heap
  dump/inspection, `Diagnostic Command`, `JvmtiEnv ForceGarbageCollection` (agents),
  `G1 Periodic Collection`, `CodeCache GC Threshold`/`Aggressive`, `Allocation Profiler` and the
  WhiteBox/test causes. Metaspace means `Metadata GC Threshold`, `Metadata GC Clear Soft
  References` or `Last ditch collection`. The names are `GCCause::to_string` in HotSpot's
  `gcCause.cpp` (jdk8u, jdk17u, mainline). Explicit and metaspace Full GCs are listed but excluded
  from Full GC rates, streaks and the leak verdict; metaspace Full GCs get their own warning
  pointing at `MetaspaceSize`.
- **Rates**: per-hour figures appear only when the window is at least `--min-rate-window` minutes;
  shorter windows show counts ("1 in 2.0 min").
- **Pause times and windows**: Java 8 logs stamp a pause when it starts, unified logs when it ends;
  the tool works with each pause's start and end. The window runs from the start of the first pause
  to the end of the last. With `--start`/`--end`, pauses that straddle a bound are kept and only the
  part inside the window counts towards time in GC and overhead.
- **Overhead**: time paused / window length, plus the **worst 1, 5 and 15 minutes** (the stretch of
  that length with the most pause time). A long quiet log cannot average an incident away: more than
  25% paused in the worst 5 minutes is a warning, more than 50% is critical.
- **Heap**: peak occupancy before GC and after GC, as a % of the max heap (`--max-heap`, then
  `-Xmx`/`MaxHeapSize` from `CommandLine flags:` of the JVM run being analysed, then the unified
  startup lines). Without any of those the committed heap is used and the report says so. "After GC"
  figures use collecting pauses only (Young, Mixed, Full): Remark, Cleanup and CMS Initial Mark log
  an occupancy, not the result of a collection. Pauses logged without heap sizes are counted in pause
  statistics but not in heap statistics.
- **Heap warnings**: judged on occupancy right after a collection that cleans the old generation
  (a Full GC, the end of a G1 mixed cycle, or a completed CMS concurrent cycle), against the
  old-generation capacity (generational collectors) or the max heap (G1). When the window has no
  such collection the live set is unknown: what is left after a young GC includes old garbage, so
  it is reported as information, never as a warning.
- **Pause warnings**: any single pause at or above the workload's limit is a warning or critical
  on its own, whatever the percentiles say. The P99 is judged only with at least 100 pauses (below
  that it is the maximum under another name), and on the slowest *kind* of pause that has 100 of
  its own, unless the all-pauses P99 is worse: thousands of 1 ms G1 Cleanup pauses otherwise hide
  a slow Remark.
- **Full GC effectiveness**: heap before minus heap after, as a % of the heap before. Old-generation
  deltas are not used: a Full GC moves surviving young objects into the old generation. A
  heap-pressure Full GC that frees less than 20% and leaves the space more than 80% full is flagged.
  "Reclaim declining" (second half of the Full GCs frees a smaller share than the first) and
  "Full GCs accelerating" (gaps shrinking) need at least 6 heap-pressure Full GCs and a
  Mann-Kendall trend (p < 0.05); they are shown as evidence beside other signals, never as alarms
  of their own.
- **Old-gen percentages**: every one names its denominator: old-generation capacity for generational
  collectors; for G1 the max heap, or the committed heap when the max is unknown.
- **Metaspace**: used sizes (first, peak, last). A percentage is shown only against
  `-XX:MaxMetaspaceSize` when the log states it: the bracketed figure on a metaspace line is reserved
  or committed space, not a limit. Growth excludes the first 10 minutes of uptime (class loading).
- **Log ends mid-collection**: a final record that was never finished (JVM killed, crashed or hung
  during a GC) is called out, with the last finished pause, how soon after it the unfinished one
  began, and how many Full GCs came right before. It is still counted as an unparsed line.
- **Old-gen floor trend (live-set growth)**: occupancy right after collections that clean the old
  generation: every Full GC; for G1 the last mixed collection of each mixed cycle (falling back to
  the heap after Remark, marked approximate, when those are too few); for CMS the old generation
  the first young collection after each concurrent sweep starts from. Floors from the first
  10 minutes of JVM uptime are listed but left out, and with several JVM runs only the latest run
  is used. A trend needs at least 3 floors spanning at least 1 hour with at least one in the
  middle third of that span (two clusters are a step, not a trend). The slope is Theil-Sen (the
  median of all pairwise slopes, with its 90% interval), whether a trend exists is the
  Mann-Kendall test, and whether it matters is the growth over the span as a share of capacity
  (≥ 5%). Growing = significant (p < 0.05) and material; "no consistent trend" = material but not
  significant; otherwise no material growth. When growing, the report gives the hours until the
  floor reaches capacity at the interval's slopes, "if growth stays linear". All floors are listed
  so you can see the trend yourself.
- **Without floors**: the lowest heap after GC in each of 12 slices of the window is an upper
  bound on the live set. If even that is flat the report says "no growth observed"; if it rises it
  says nothing about the live set (it may be garbage no collection has removed yet).
- **Step change**: a floor at least twice the median of the floors before it, and higher by at
  least 10% of capacity, is reported as "live set jumped from X to Y" with both times. That is a
  retention event (a very large request, a batch load), not gradual growth: the leak verdict is
  "step change", not "growing".
- **Timeline**: the window in equal slices (1 min up to 1 day, at most 48 rows) with pauses, share
  of time paused, longest pause, Full GCs and the heap after the last collecting GC.
- **GC CPU time**: from `[Times: user= sys= real=]` / unified `gc,cpu`. Pauses of 0.1 s or more are
  flagged when sys is over 20% of user (kernel memory work) or real is over 1.5 times user+sys (the
  collector was waiting). A warning needs at least 3 such pauses and 5% of the judged pauses. The
  median (user + sys) ÷ real per kind of pause shows how many threads' worth of CPU the collector
  used.
- **Concurrent GC work**: G1 concurrent cycle durations (unified), G1 concurrent-mark phases
  (Java 8) and CMS concurrent mark/sweep phases: count, total and share of the window. It runs
  alongside the application and is not part of pause overhead; 25% or more is a warning. When all
  cycles fall in a small part of the window (e.g. start-up), the report gives their time range
  instead of an average "one every".
- **Safepoints**: from "Total time for which application threads were stopped" lines (Java 8
  `-XX:+PrintGCApplicationStoppedTime`, JDK 9-12 `-Xlog:safepoint`) and JDK 13+
  `Safepoint "<operation>", ... Reaching safepoint: N ns, ... Total: N ns` lines (the field list of
  `SafepointTracing::end` in jdk13u, jdk17u, jdk21u and mainline): total stopped time, safepoints
  that needed 1 s or more to stop the threads, and stops that no GC pause overlaps. Those are
  freezes heap tuning cannot fix (thread dumps, deoptimization, ...); one at or above the
  workload's single-stop limit is a warning or critical, with the VM operation named.
- **G1 marking and humongous objects**: a pause whose cause is "G1 Humongous Allocation" that
  starts marking only says when G1 noticed its marking threshold was exceeded (it checks at every
  humongous allocation), so the cause alone is never reported as a humongous problem. Humongous
  objects are judged from the `Humongous regions` counts: a median of 10% or more of the heap, or
  humongous allocation of 20% or more of all allocation, is a warning. Marking cycles more often
  than 6 an hour are reported with where marking starts and where the old generation stays after
  each mixed cycle.
- **Start-up**: a G1 evacuation failure in the first 10 minutes of uptime is reported as
  information (the heap is still growing to its working size), not as a warning. When the
  committed heap changes during the window, a data note says `-Xms` is below `-Xmx`.
- **JVM & host**: JVM version, CPUs, physical memory and swap from the log header (Java 8 header
  lines, JDK 17+ `gc,init`, which also gives the minimum and initial heap and the parallel and
  concurrent worker counts). A max heap larger than physical memory is a warning.
- **Leak verdict**: one of *growing* (the floor trend above), *step change*, *full* (live data
  above the heap warning threshold without a growth trend), *none* (no material growth in the
  floors, or a flat upper bound without floors) or *not assessed*, each with its evidence. There is
  no score.
- **Allocation rate**: occupancy before GC *n* minus occupancy after GC *n-1*, divided by the time
  the application ran between them (pause time and downtime between JVM runs left out). Young
  generation when logged; whole heap for G1 (which includes humongous allocation) and when young
  sizes are missing.
- **Promotion**: old-generation growth across young GCs, as an average over all young GCs, a total and
  a rate. For G1 only the `Old regions` count is used, so humongous regions freed in the same pause
  do not cancel what was promoted.
- **Promotion failure**: a young collection that could not move survivors into the old generation
  (`--[PSYoungGen`, `ParNew (promotion failed)`, ...) is critical for every generational collector.
- **Decimal comma**: logs written by a JVM under a decimal-comma locale (`0,0301 secs`,
  `10,500ms`) are read like any other.
- **Thrashing**: `--full-gc-streak` heap-pressure Full GCs back to back, the last starting within
  5 minutes of the first one ending (so 150-second Full GCs 30 seconds apart count).
- **JVM runs**: a new segment starts when uptime goes backwards, or when a JVM start header
  (`CommandLine flags:` / `Using <collector>`) appears after GC events. With `--segment all` the
  window is the time the JVMs were running: downtime between runs is left out of overhead and
  rates. Without wall-clock time the runs overlap on the time axis, so the timeline and worst
  stretches are not shown.
- **Premature promotion**: with `-XX:+PrintHeapAtGC` (Java 8), a young collection that leaves the
  survivor space at least 99% full while the old generation grows has overflowed it. Three or more
  is a warning, with the count, the time range and how much was promoted.
- **Not assessed**: Data Notes name each thing the log could not show and the logging option that
  adds it: pause CPU times, application-stopped time, JVM uptime, survivor occupancy, and
  concurrent collector work.
- **Warning codes**: each health warning has a stable code (`GCSummary.health_warnings`), which is
  how findings find the warnings they explain; the wording can change without breaking that.

## Report sections

The report leads with what is wrong and what to do, then shows when, then how far the data can be
trusted, then the detail.

1. **Incomplete Parse** (only when > 1% of GC lines were not understood).
2. **Diagnosis** (when a finding names a cause): one paragraph that puts the cause first and its
   consequences after it.
3. **Findings**: every problem the analysis flagged, most severe first and, within a severity,
   causes before symptoms. Each has a severity (critical / warning / info), when it happened, the
   evidence from the log, a confidence (high: read straight off the log; medium: an
   interpretation of it), an action, and the documentation the action restates. Every health
   warning is explained by exactly one finding. When the heap ran out of room, tuning advice for
   consequences (survivor sizing, metaspace, collector choice) is marked secondary.
4. **Summary**: status, leak verdict, window, pauses by kind, time in GC, worst 5 minutes, P99 (and
   of which kind) and the longest pause, whether the longest pauses cluster, heap after GC,
   occupancy after old-gen cleanup, Full GCs by cause, the live-set trend and data quality.
5. **Timeline**, and **Compared with the same window 24 h earlier** (with `--start`/`--end`).
6. **Data Notes** (limits of this log), **Parsing Coverage**, **Input Files** (several files),
   **JVM Runs Found** (restarts), **Time Window**.
7. **JVM & Host**, **JVM Heap & GC Tuning Configuration**.
8. **GC Frequency**, **Full GC Causes**, **Pause Causes by Kind**, **GC Overhead**,
   **Heap Utilization**, **Pause Time Analysis**, **Pause Threshold Violations**,
   **Top 10 Longest Pauses**.
9. **Old-Gen Floor Trend** and the **Floors** table, **Old Generation**,
   **Trend (Early / Middle / Late)**, **Allocation Pressure**, **G1 GC Metrics** /
   **CMS GC Metrics**, **Concurrent GC Work**, **GC CPU Time**, **Safepoints**, **Metaspace**,
   **Live Set and Leak Assessment**.

`--output` writes the same sections as Markdown. `--brief` keeps the diagnosis, every critical and
warning finding (one line each, up to 12 with informational ones filling what is left), the
summary, the five timeline slices with the most time paused, data notes and quality, Full GC
causes, the longest pauses, the floor trend and key JVM flags, within ~5 KB. When space runs short
it sheds floors, pause rows, finding times, informational findings and data notes, in that order;
the critical and warning findings and the summary always stay. Wide tables wrap rather than cut
off a time or a cause.

### Where the advice comes from

Actions in the findings come from one table, `src/gc_analyze/advice.py`. Each entry restates what
the cited document says and names it: the HotSpot GC Tuning Guides for Java 8 and JDK 17 (G1
entries also checked against JDK 21), the JDK 17 `java` and `jcmd` references, JEP 307 / JEP 423,
and the Tomcat 9 configuration reference. On a max heap of 32 GB or more the class histogram
(`jcmd <pid> GC.class_histogram`) is suggested before a full heap dump, and the report says
whether `-XX:+HeapDumpOnOutOfMemoryError` is already set. Advice that depends on the release is chosen from the JVM
version in the log header (a Java 8 style log without a header is treated as Java 8; a unified log
without a version is treated as JDK 9 or later). Collector flags are tuning options, not fixes:
confirm a change against the documentation for the release you run.

Changed in 6.0.0: the exit code and Status follow the findings (a growing live set or a
log that ends mid-collection now counts); the leak score is replaced by a verdict; the default
pause limits are the `server` workload (`--workload batch` restores the old ones); a heap that is
only full after young GCs is no longer called live data; promotion failures count for every
collector; JDK 13+ safepoint lines are read; JVMTI and periodic Full GCs are no longer counted as
heap pressure.

Changed in 5.0.0: the Incident Summary, Quick Diagnosis, At-a-Glance, JVM Runtime Overview,
Evidence-Based Recommendations, Warnings and Overall Status sections were merged into Findings and
Summary.

## Exported events (`--export-events`)

One JSON object per pause, following the shared `events.jsonl` format: `ts` (UTC, ms precision),
`ts_raw` (as logged), `tz_source` (`in-line`, `cli:<jvm start>` or `assumed:UTC`), `source: "gc"`,
`host`, `file`, `line`, `level` (`WARN` for heap-pressure Full GCs and failures, else `INFO`),
`message`, `template`, `signature`, `duration_ms`, and `attrs` with `kind`, `cause`,
`heap_before_kb`, `heap_after_kb`, `heap_committed_kb`, `max_heap_kb`, `old_after_kb`, `uptime_s`,
`segment` and any failure flags. Logs with uptime only need `--jvm-start`.

## Checking accuracy

- `scripts/crosscheck.py` tallies a log with separate, simpler logic and compares pause counts by
  kind, total pause time, the longest pause, summed heap sizes, the last old-generation size, the
  last metaspace size and the number of safepoint lines with the tool (logs with a decimal comma
  are not read by it):

  ```bash
  uv run python scripts/crosscheck.py path/to/gc.log
  ```

## Development

Use Python 3.15 and the latest stable dependency releases compatible with it. Runtime, development,
and build dependency minimums are declared in `pyproject.toml`; keep them current when upgrading.

```bash
uv sync --upgrade --extra dev
uv run --frozen --extra dev ruff format --check
uv run --frozen --extra dev ruff check
uv run --frozen --extra dev basedpyright
```

Verification targets Python 3.15 only. See `AGENTS.md` for the full verification sequence.

The test suite (golden-file fixtures with hand-computed expected results) is kept by the
maintainer and is not part of this repository.

Modules: `parsers` (formats and detection), `events` (normalization), `coverage`, `segments`
(restarts, multiple files, windows), `analysis` (statistics, floors, leak verdict), `findings`
(ranked findings, status, diagnosis), `advice`, `jvm_config`,
`pipeline` (files → summary), `report` (sections + terminal), `markdown`, `export`, `cli`.
