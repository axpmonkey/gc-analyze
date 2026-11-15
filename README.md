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
uv sync
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
| `--heap-warning`, `--heap-critical PCT` | Heap-after-GC thresholds (default `80` / `95`) |
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

Exit codes: `0` clean, `1` warnings or an incomplete parse (> 1% of GC lines not understood),
`2` critical issues (any `CRITICAL` warning, or a High/Critical leak level).

## How the numbers are defined

- **Pauses**: every stop-the-world pause: Young, Mixed (G1), Full, Initial Mark and Remark (CMS),
  Remark and Cleanup (G1). G1 `Prepare Mixed` and `Concurrent Start` pauses are young pauses. A young
  collection that collects the old generation in the same pause (CMS/Serial promotion failure or
  concurrent mode failure) counts as a Full GC with the failure flagged.
- **Full GC causes**: each Full GC is *heap pressure*, *explicit* (`System.gc()`, heap dump/inspection,
  diagnostic command) or *metaspace* (`Metadata GC Threshold`, `Last ditch collection`). Explicit and
  metaspace Full GCs are listed but excluded from Full GC rates, streaks, acceleration and leak
  scoring; metaspace Full GCs get their own warning pointing at `MetaspaceSize`.
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
  (a Full GC, or the end of a G1 mixed cycle), against the old-generation capacity (generational
  collectors) or the max heap (G1). Only when the log has no such collection is the peak after a
  young GC used.
- **Full GC effectiveness**: heap before minus heap after, as a % of the heap before. Old-generation
  deltas are not used: a Full GC moves surviving young objects into the old generation. A
  heap-pressure Full GC that frees less than 20% and leaves the space more than 80% full is flagged.
- **Old-gen percentages**: every one names its denominator: old-generation capacity for generational
  collectors; for G1 the max heap, or the committed heap when the max is unknown.
- **Metaspace**: used sizes (first, peak, last). A percentage is shown only against
  `-XX:MaxMetaspaceSize` when the log states it: the bracketed figure on a metaspace line is reserved
  or committed space, not a limit. Growth excludes the first 10 minutes of uptime (class loading).
- **Log ends mid-collection**: a final record that was never finished (JVM killed, crashed or hung
  during a GC) is called out at the top. It is still counted as an unparsed line.
- **Old-gen floor trend (live-set growth)**: occupancy right after collections that clean the old
  generation: every Full GC, and for G1 the last mixed collection of each mixed cycle (falling back
  to the heap after Remark, marked approximate, when those are too few). Floors from the first
  10 minutes of JVM uptime are listed but left out of the trend. A least-squares slope (MB/h or
  GB/h) is reported when there are at least 3 floors spanning at least 1 hour with at least one in
  the middle third of that span (two clusters always fit a line); otherwise the report says "not
  assessed" and why. A rising floor means the live set is growing: a leak, a cache still filling,
  or more load. All floors are listed so you can see the trend yourself.
- **Step change**: a floor at least twice the median of the floors before it, and higher by at
  least 10% of capacity, is reported as "live set jumped from X to Y" with both times. That is a
  retention event (a very large request, a batch load), not gradual growth, and is not scored as
  a leak.
- **Timeline**: the window in equal slices (1 min up to 1 day, at most 48 rows) with pauses, share
  of time paused, longest pause, Full GCs and the heap after the last collecting GC.
- **GC CPU time**: from `[Times: user= sys= real=]` / unified `gc,cpu`. Pauses of 0.1 s or more are
  flagged when sys is over 20% of user (kernel memory work) or real is over 1.5 times user+sys (the
  collector was waiting). A warning needs at least 3 such pauses and 5% of the judged pauses.
- **Concurrent GC work**: G1 concurrent cycle durations (unified), G1 concurrent-mark phases
  (Java 8) and CMS concurrent mark/sweep phases: count, total and share of the window. It runs
  alongside the application and is not part of pause overhead; 25% or more is a warning.
- **Safepoints**: when the log has "Total time for which application threads were stopped" lines
  (Java 8 `-XX:+PrintGCApplicationStoppedTime`, JDK 9-12 `-Xlog:safepoint`), total stopped time and
  safepoints that needed 1 s or more to stop the threads. The JDK 13+ safepoint line format is not
  parsed.
- **JVM & host**: JVM version, CPUs, physical memory and swap from the log header (Java 8 header
  lines, JDK 17+ `gc,init`). A max heap larger than physical memory is a warning.
- **Leak score (0-100)**: floor slope (with a fit of r² ≥ 0.5), declining heap reclaim per Full GC,
  accelerating heap-pressure Full GCs, the latest floor close to capacity, and headroom after GC.
  Without floors the leak level is "not assessed", never "None".
- **Allocation rate**: occupancy before GC *n* minus occupancy after GC *n-1*, summed over the window
  (young generation when logged, else whole heap). For G1 this excludes humongous allocations, which
  go straight into old-generation regions.
- **Promotion**: old-generation growth across young GCs, as an average over all young GCs, a total and
  a rate.
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
2. **Findings**: every problem the analysis flagged, most severe first. Each has a severity
   (critical / warning / info), when it happened, the evidence from the log, a confidence (high:
   read straight off the log; medium: an interpretation of it), an action, and the JDK
   documentation the action restates. Every health warning is explained by exactly one finding.
3. **Summary**: status, leak risk, window, pauses by kind, time in GC, worst 5 minutes, P99 and
   longest pause, whether the longest pauses cluster, heap after GC, occupancy after old-gen
   cleanup, Full GCs by cause, the live-set trend and data quality.
4. **Timeline**, and **Compared with the same window 24 h earlier** (with `--start`/`--end`).
5. **Data Notes** (limits of this log), **Parsing Coverage**, **Input Files** (several files),
   **JVM Runs Found** (restarts), **Time Window**.
6. **JVM & Host**, **JVM Heap & GC Tuning Configuration**.
7. **GC Frequency**, **Full GC Causes**, **Pause Causes by Kind**, **GC Overhead**,
   **Heap Utilization**, **Pause Time Analysis**, **Pause Threshold Violations**,
   **Top 10 Longest Pauses**.
8. **Old-Gen Floor Trend** and the **Floors** table, **Old Generation**,
   **Trend (Early / Middle / Late)**, **Allocation Pressure**, **G1 GC Metrics** /
   **CMS GC Metrics**, **Concurrent GC Work**, **GC CPU Time**, **Safepoints**, **Metaspace**,
   **Memory Leak Assessment**.

`--output` writes the same sections as Markdown. `--brief` keeps every critical and warning finding
(one line each, up to 12 with informational ones filling what is left), the summary, the five
timeline slices with the most time paused, data notes and quality, Full GC causes, the longest
pauses, the floor trend and key JVM flags, within ~5 KB. When space runs short it sheds floors and
pause rows before it touches the findings.

### Where the advice comes from

Actions in the findings come from one table, `src/gc_analyze/advice.py`. Each entry restates what
the cited document says and names it: the HotSpot GC Tuning Guides for Java 8 and JDK 17, the JDK 17
`jcmd` reference, and JEP 307 / JEP 423. Advice that depends on the release is chosen from the JVM
version in the log header (a Java 8 style log without a header is treated as Java 8; a unified log
without a version is treated as JDK 9 or later). Collector flags are tuning options, not fixes:
confirm a change against the documentation for the release you run.

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

- `scripts/crosscheck.py` tallies pauses from a log with separate, simpler logic and compares counts by
  kind, total pause time and the longest pause with the tool:

  ```bash
  uv run python scripts/crosscheck.py path/to/gc.log
  ```

## Development

```bash
ruff format --check && ruff check && basedpyright
```

The test suite (golden-file fixtures with hand-computed expected results) is kept by the
maintainer and is not part of this repository.

Modules: `parsers` (formats and detection), `events` (normalization), `coverage`, `segments`
(restarts, multiple files, windows), `analysis` (statistics, floors, leak score), `jvm_config`,
`pipeline` (files → summary), `report` (sections + terminal), `markdown`, `export`, `cli`.
