# gc-analyze

`gc-analyze` reads Java garbage collection (GC) logs and reports pause times, heap pressure,
and signs of growing memory retention. Use it to investigate application stalls, frequent Full
GCs, or a JVM that appears to be running out of heap.

The report includes findings with supporting evidence and suggested actions. You can read it in
the terminal, save it as Markdown, or export individual pauses as JSON Lines for a timeline.

## Install and run

You need Git, [uv](https://docs.astral.sh/uv/getting-started/installation/), and a GC log to analyze.
The application supports **Python 3.14 and 3.15**. The setup example uses Python 3.15.
A Java installation is not required to analyze an existing log.

### 1. Install uv

On macOS or Linux:

```sh
curl -LsSf https://astral.sh/uv/install.sh | sh
```

On Windows, run in PowerShell:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

Restart your terminal if `uv` is not available after installation. For other installation
methods, see the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

### 2. Download and set up the application

```sh
git clone https://github.com/axpmonkey/gc-analyze.git
cd gc-analyze
uv python install 3.15
uv sync --python 3.15
uv run --frozen gc-analyze version
```

The first sync creates the local lockfile. The last command displays the installed application
version. Setup downloads Python and the project dependencies, so it requires network access.

To use Python 3.14, run `uv python install 3.14` and `uv sync --python 3.14`. Pass
`--python 3.14` to `uv run` as well to select it explicitly.

### 3. Analyze a log

From the `gc-analyze` directory, run:

```sh
uv run --frozen gc-analyze analyze /path/to/gc.log
```

Replace `/path/to/gc.log` with your log file. Quote paths that contain spaces, for example
`"C:\Logs\Java App\gc.log"`. No environment activation is needed.

Start with **Findings** and **Summary**, then check **Data Notes** and **Parsing Coverage** to
understand the limits of the analysis. A nonzero exit code can indicate a problem found in the
log even when the report was generated successfully; see [Exit codes](#exit-codes).

## Supported logs

The application detects the format and collector automatically.

| Log format | Supported collectors |
|---|---|
| Java 8: `-XX:+PrintGC` or `-XX:+PrintGCDetails` | G1, Parallel, CMS, Serial, and ParNew with Serial Old |
| JDK 9 and later: unified `-Xlog:gc*` logging | G1, Parallel, CMS, and Serial, where available in that JDK |

ZGC, Shenandoah, and Epsilon logs are not supported. Basic Java 8 `PrintGC` logs can provide
pause and heap statistics without identifying the collector or exposing all diagnostic data.

Supply plain-text log files from **one JVM**, including its rotated files if needed. Files with
different collectors must be analyzed separately. Extract compressed logs before running the
application. Keep startup headers and detailed GC records when available: they provide heap
limits, JVM configuration, and evidence needed for more complete findings.

Both dated logs and logs containing only JVM uptime are supported. Uptime alone is sufficient
for a general report; selecting a clock-time window or exporting events requires dated records
or a JVM start time supplied with `--jvm-start`.

## Common tasks

### Save a report

Write a full Markdown report while also displaying the terminal report:

```sh
uv run --frozen gc-analyze analyze gc.log --output gc-report.md
```

Write a compact Markdown summary suitable for an incident record:

```sh
uv run --frozen gc-analyze analyze gc.log --brief --output gc-brief.md
```

Without `--output`, `--brief` writes Markdown to standard output. Output paths are relative to
the current directory unless absolute. Create the destination directory first; existing output
files are overwritten.

### Analyze rotated files or JVM restarts

Pass the rotated files together. The application orders them by their recorded times:

```sh
uv run --frozen gc-analyze analyze gc.log.0 gc.log.1 gc.log.2.current
```

When the input includes restarts, each detected JVM run becomes a numbered **segment**. By
default, only the latest segment is analyzed. Use the **JVM Runs Found** table to choose another:

```sh
uv run --frozen gc-analyze analyze gc.log --segment 1
uv run --frozen gc-analyze analyze gc.log --segment all
```

With `--segment all`, rates use the combined observed JVM time. Heap limits are shown by run,
and the retention trend uses the latest selected run. Without wall-clock timestamps, combined runs cannot produce
a timeline or worst-period overhead figures.

### Investigate a time window

Use ISO 8601 timestamps, preferably with an explicit UTC offset:

```sh
uv run --frozen gc-analyze analyze gc.log --start 2026-11-10T14:00:00-05:00 --end 2026-11-10T14:30:00-05:00
```

Either boundary can be used alone. With both boundaries, the report also compares the same window
24 hours earlier if the supplied logs contain pauses in that earlier window.

A timestamp without an offset uses the log's offset. Log datestamps that omit an offset are
interpreted as UTC. A pause counts if it overlaps the interval. Its full duration contributes to
percentiles and longest-pause statistics, while only the part inside the interval contributes
to pause share. The report uses the requested duration when log timestamps cover its bounds.
Otherwise it shows the observed bounds and labels the share accordingly. Timestamp coverage
does not verify that rotation files or individual records are complete.

For an uptime-only log, provide the actual JVM start time, including its offset:

```sh
uv run --frozen gc-analyze analyze gc.log --jvm-start 2026-11-10T08:00:00-05:00
```

### Supply the maximum heap or change pause limits

If the log does not record the maximum heap, supply the JVM's configured `-Xmx` value:

```sh
uv run --frozen gc-analyze analyze gc.log --max-heap 4g
```

The default `server` workload uses pause limits for request-serving applications. Use `batch`
for a workload where longer pauses are acceptable:

```sh
uv run --frozen gc-analyze analyze gc.log --workload batch
```

| Pause measure | Server warning / critical | Batch warning / critical |
|---|---|---|
| Any single GC pause or other safepoint stop | ≥ 5 s / ≥ 30 s | ≥ 60 s / ≥ 300 s |
| P99 GC pause | > 1 s / > 5 s | > 5 s / > 10 s |

P99 warnings require at least 100 pauses. The assessment also checks individual pause kinds with
at least 100 samples, so frequent short pauses do not hide a slower kind.

### Analyze rotated logs or a specific time window

Pass rotated files together; they are ordered by their logged timestamps:

```sh
uv run --frozen gc-analyze analyze gc.log.0 gc.log.1 gc.log.2.current
```

When the input spans JVM restarts, the latest run is analyzed by default. Use `--segment all`
to include all runs, or `--segment 1` to select a run by its number in **JVM Runs Found**.

To focus on an incident:

```sh
uv run --frozen gc-analyze analyze gc.log --start 2026-11-10T14:00:00-05:00 --end 2026-11-10T14:30:00-05:00
```

Use ISO 8601 dates and times. An explicit UTC offset avoids ambiguity; without one, the log's
offset is used. Uptime-only logs need `--jvm-start`, for example
`--jvm-start 2026-11-10T08:00:00-05:00`. With both window bounds, a comparison with the same
window 24 hours earlier is included when earlier pauses are available in the input.

### Export pauses for a timeline

```sh
uv run --frozen gc-analyze analyze gc.log --export-events gc.events.jsonl --host app-03
```

The export contains one JSON object per analyzed GC pause. It requires wall-clock time; add
`--jvm-start` for an uptime-only log. It can be combined with `--output` and window selection.

Each record includes a UTC timestamp (`ts`), duration in milliseconds (`duration_ms`), source
file and line, optional host, and a readable message. The `attrs` object includes the pause kind,
cause, heap sizes in KB, JVM uptime, segment number, and any failure flags. `ts_raw` and
`tz_source` preserve the timestamp's origin. `level` is `WARN` for heap-pressure Full GCs and
collection failures, and `INFO` otherwise; it is separate from the report's overall status.

## Understand the report

Sections appear when the log contains the necessary data. Findings include severity, evidence,
confidence, and a recommended action with a documentation reference.

| Report item | Meaning |
|---|---|
| **Status** | Severity of the assessed JVM signals. The summary lists material measurement gaps. |
| **Pauses** | Stop-the-world collections and GC phases, grouped by kind, such as Young, Mixed, Full, or Remark. |
| **P50 / P95 / P99** | Pause durations at the 50th, 95th, and 99th percentiles. P50 is the median; P99 describes the slow end of the distribution. Check the sample count and longest pause as well. |
| **Time in GC pauses / pause share** | Elapsed time covered by logged GC pauses and its share of the reported time basis. |
| **Worst 5 minutes** | The five-minute stretch with the highest pause overhead, exposing incidents that a whole-log average can hide. |
| **Heap after GC** | Memory remaining after a collecting pause. A high value after a young collection can include old garbage that has not yet been collected. |
| **Highest post-Full-GC occupancy** | Heap remaining after Full GC as a share of that run's maximum, when known. |
| **Full GC causes** | Heap pressure, explicit requests, metaspace, other known triggers, or unknown. Only recognized heap-pressure causes contribute to heap-pressure rates and streaks. |
| **Post-GC Occupancy Trend** | A comparison of like collection types in one JVM run. A sustained rise warrants inspecting retention and workload. |
| **Safepoint Timing** | Total elapsed time, time reaching the safepoint and time at it, where logged. VM operations and GC overlap are used to identify known and unmatched events. |
| **Timeline** | Counts, overhead, longest pause, Full GCs, and heap occupancy in time slices. |
| **Data Notes / Parsing Coverage** | Missing measurements, assumptions, and GC lines the parser could not understand. Coverage describes all supplied files, even when a segment or window is selected. |

Without a selected window, duration runs from the first pause's start to the last pause's end.
Per-hour rates are shown only for windows of at least 60 minutes by default; shorter windows show
counts. Heap percentages use the maximum heap when known and committed heap otherwise. The
report names the basis; old-generation percentages use old-generation capacity where available.

### Interpret the retention assessment

The report evaluates comparable whole-heap samples after Full GC, after a confirmed G1
Mixed sequence, or old-generation samples after CMS sweep. It fits a trend within one
measurement type and one run. The default trend needs three samples over at least an hour,
with a sample in the middle third. The first 10 minutes of uptime are excluded from the trend.

Post-Mixed and post-sweep occupancy can include unreclaimed objects. A Mixed sequence that
ends at the log boundary is marked unconfirmed. Heap remaining after Young GC is an upper
bound and leaves retention growth unassessed, even if that bound stays flat. G1 region counts
measure the footprint of the occupied regions.

A sustained rise or a step up is evidence to correlate with workload, deployments, caches
and retained objects. High occupancy after Full GC can signal heap pressure even with too
few samples to establish a trend.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Analysis completed without warning or critical findings. Informational findings may be present. |
| `1` | Warning finding, more than 1% of candidate GC lines unparsed, or an analysis/export error. |
| `2` | Critical finding, or a command-line usage error. Read the report or error message to distinguish them. |

Reports and exports are written before an exit caused by findings. In scripts, retain the exit
code and inspect the report; a nonzero code does not necessarily mean the command failed to run.

## Troubleshooting and help

| Problem | What to check |
|---|---|
| `uv` is not found | Restart the terminal and check the uv installer's PATH instructions. |
| Python version error | Run `uv python install 3.14`, then `uv sync --python 3.14` from the project directory. Use `3.15` in both commands if you prefer it. |
| Unsupported format or no usable GC events | Confirm that the file is an extracted, plain-text GC log for a supported collector. Check any unparsed samples in the error. |
| Incomplete parse | Review **Parsing Coverage** and its sample lines. Missing records can affect counts and conclusions. Use `--verbose` for per-file parsing details. |
| Time window or export needs wall-clock time | Supply `--jvm-start` with the actual start time and UTC offset, or use logs containing datestamps. |
| Heap percentages use committed heap | Supply the configured maximum with `--max-heap`, or include the startup log that records it. |
| Retention trend is not assessed | Check **Data Notes** and **Post-GC Occupancy Trend** for the available samples and why they were insufficient. |

For the full option list:

```sh
uv run --frozen gc-analyze analyze --help
```
