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
| `--full-gc-streak N` | Heap-pressure Full GCs within 5 minutes that count as thrashing (default `3`) |
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
- **Heap**: peak occupancy before GC and after GC, as a % of the max heap (`--max-heap`, then
  `-Xmx`/`MaxHeapSize` from `CommandLine flags:`, then the unified startup lines). Without any of those
  the committed heap is used and the report says so. Pauses logged without heap sizes are counted in
  pause statistics but not in heap statistics.
- **Old-gen floor trend (leak signal)**: occupancy right after collections that clean the old
  generation: every Full GC, and for G1 the last mixed collection of each mixed cycle (falling back
  to the heap after Remark, marked approximate, when those are too few). A least-squares slope in
  MB/h is reported when there are at least 3 floors spanning at least 1 hour; otherwise the report
  says "not assessed" and why. All floors are listed so you can see the trend yourself.
- **Leak score (0-100)**: floor slope (with a fit of r² ≥ 0.5), declining reclamation per Full GC,
  accelerating heap-pressure Full GCs, the latest floor close to capacity, and headroom after GC.
  Without floors the leak level is "not assessed", never "None".
- **Allocation rate**: occupancy before GC *n* minus occupancy after GC *n-1*, summed over the window
  (young generation when logged, else whole heap).
- **Thrashing**: `--full-gc-streak` heap-pressure Full GCs inside any 5-minute window.
- **JVM runs**: a new segment starts when uptime goes backwards, or when a JVM start header
  (`CommandLine flags:` / `Using <collector>`) appears after GC events.

## Report sections

1. **Incomplete Parse** (only when > 1% of GC lines were not understood).
2. **Incident Summary**: window, the five worst pauses with time, kind and cause, whether they cluster,
   the live-set trend, Full GC causes and data quality.
3. **Data Notes**: limits of this log (short window, no wall clock, no max heap, no old-gen sizes,
   floor trend not assessed, explicit Full GCs excluded).
4. **Parsing Coverage**, **Input Files** (several files), **JVM Runs Found** (restarts), **Time Window**,
   **Compared with the same window 24 h earlier** (with `--start`/`--end`).
5. **JVM Heap & GC Tuning Configuration**, **Quick Diagnosis**, **At-a-Glance**.
6. **Runtime overview**, **GC Frequency**, **Full GC Causes**, **Pause Causes by Kind**, **GC Overhead**,
   **Heap Utilization**, **Pause Time Analysis**, **Pause Threshold Violations**, **Top 10 Longest Pauses**.
7. **Old-Gen Floor Trend** and the **Floors** table, **Old Generation**, **Trend (Early / Middle / Late)**,
   **Allocation Pressure**, **G1 GC Metrics** / **CMS GC Metrics**, **Metaspace**.
8. **Memory Leak Assessment**, **Evidence-Based Recommendations** (tied to the JVM's own flags),
   **Warnings**, **Overall Status**.

`--output` writes the same sections as Markdown; `--brief` keeps the incident summary, data notes and
quality, Full GC causes, top 10 pauses, the floor trend (floors sampled evenly), key JVM flags and
warnings, within ~5 KB.

## Exported events (`--export-events`)

One JSON object per pause, following the shared `events.jsonl` format: `ts` (UTC, ms precision),
`ts_raw` (as logged), `tz_source` (`in-line`, `cli:<jvm start>` or `assumed:UTC`), `source: "gc"`,
`host`, `file`, `line`, `level` (`WARN` for heap-pressure Full GCs and failures, else `INFO`),
`message`, `template`, `signature`, `duration_ms`, and `attrs` with `kind`, `cause`,
`heap_before_kb`, `heap_after_kb`, `heap_committed_kb`, `max_heap_kb`, `old_after_kb`, `uptime_s`,
`segment` and any failure flags. Logs with uptime only need `--jvm-start`.

## Checking accuracy

- `tests/fixtures/*.log` are stock-format logs, each with a hand-computed `*.expected.json`
  (counts by kind and cause, pause count/sum/min/max, first/last time, coverage, failure flags, floors
  and slope, max heap). `tests/test_golden.py` diffs the tool against them.
- `scripts/crosscheck.py` tallies pauses from a log with separate, simpler logic and compares counts by
  kind, total pause time and the longest pause with the tool:

  ```bash
  uv run python scripts/crosscheck.py path/to/gc.log
  ```

## Development

```bash
ruff format --check && ruff check && basedpyright && pytest -q --cov=src/gc_analyze --cov-branch --cov-fail-under=90
```

Modules: `parsers` (formats and detection), `events` (normalization), `coverage`, `segments`
(restarts, multiple files, windows), `analysis` (statistics, floors, leak score), `jvm_config`,
`pipeline` (files → summary), `report` (sections + terminal), `markdown`, `export`, `cli`.
