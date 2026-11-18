# gc-analyze

`gc-analyze` reads Java garbage collection (GC) logs and reports pause times, heap pressure,
and signs of growing memory retention. Use it to investigate application stalls, frequent Full
GCs, or a JVM that appears to be running out of heap.

The report lists findings with their evidence and a suggested action for each. Read it in the
terminal, or save it as Markdown or JSON. You can also export every pause as JSON Lines for a
timeline tool.

## Install

You need [uv](https://docs.astral.sh/uv/). You do not need Java to analyze a log.

1. Install uv.

   On macOS or Linux:

   ```sh
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

   On Windows, in PowerShell:

   ```powershell
   powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
   ```

   For other methods, see the [uv installation guide](https://docs.astral.sh/uv/getting-started/installation/).

2. Install gc-analyze:

   ```sh
   uv tool install git+https://github.com/axpmonkey/gc-analyze
   ```

   uv selects a supported Python (3.14 or 3.15) and downloads it if none is installed, so
   installation needs network access.

3. Check the installation:

   ```sh
   gc-analyze version
   ```

   If the command is not found, run `uv tool update-shell` and open a new terminal.

To upgrade, run `uv tool upgrade gc-analyze`. To remove it, run `uv tool uninstall gc-analyze`.

### Run from a clone

To work on the code, clone the repository and run the command through uv:

```sh
git clone https://github.com/axpmonkey/gc-analyze.git
cd gc-analyze
uv sync
uv run gc-analyze analyze /path/to/gc.log
```

## Quick start

```sh
gc-analyze analyze /path/to/gc.log
```

On Windows, quote a path that contains spaces:

```powershell
gc-analyze analyze "C:\Logs\Java App\gc.log"
```

Read **Findings** and **Summary** first. Then check **Data Notes** and **Parsing Coverage** to
see what the log could not show. The [exit code](#exit-codes) gives the overall result: `0`
when nothing needs attention, `1` for warnings, `2` for critical findings, and `3` when the log
could not be analyzed.

This excerpt comes from a short Java 8 CMS log in which the old generation filled before
concurrent cycles could finish:

```text
## Summary

- **Status:** CRITICAL - ACTION REQUIRED
- **Pauses:** 142 (54 Young, 6 Full, 43 Initial Mark, 39 Remark)
- **Time in GC pauses:** 0.848s. Pause share of the observed pause span 14.32% (over the 10% warning limit)
- **Longest pause:** 0.026s (Full, Allocation Failure) at 2026-11-18T10:54:04.537+00:00
- **Full GCs:** 6 (4 Allocation Failure, 2 System.gc())

## Findings

- [CRITICAL] CMS fell back to stop-the-world collections [high confidence]. 4 CMS concurrent mode failure(s) - old gen filled before the concurrent cycle finished
- [WARNING] GC pauses take 14.3% of the observed pause span [high confidence]. 0.848 s paused in 5.92 s
- [INFO] Full GCs are being requested explicitly [high confidence]. 2 Full GC(s) not caused by heap pressure (2 System.gc()), 0.042 s paused in total
```

## Supported Java versions and collectors

`gc-analyze` reads GC logs from HotSpot-based JDKs: Oracle JDK and OpenJDK builds such as
Eclipse Temurin, Amazon Corretto, Azul Zulu, and the Red Hat build of OpenJDK. It supports
**Java 8** and **JDK 9 and later**, and detects the log format and the collector automatically.

### Collectors

| Collector | Selected by | Java 8 | JDK 9 and later |
|---|---|---|---|
| G1 | `-XX:+UseG1GC` | Supported | Supported |
| Parallel | `-XX:+UseParallelGC` | Supported | Supported |
| Parallel with Serial Old | `-XX:+UseParallelGC -XX:-UseParallelOldGC` | Supported | Through JDK 14 (removed in JDK 15) |
| CMS (ParNew with Concurrent Mark Sweep) | `-XX:+UseConcMarkSweepGC` | Supported | Through JDK 13 (removed in JDK 14) |
| Serial | `-XX:+UseSerialGC` | Supported | Supported |
| ParNew with Serial Old | `-XX:+UseParNewGC` | Supported | Removed in JDK 9 |

If no collector is selected, the JVM chooses one. With at least 2 CPUs and 1792 MB of memory,
Java 8 chooses Parallel and JDK 9 and later choose G1. With less, both choose Serial. The JVM
counts only the CPUs and memory a container is limited to, so a Tomcat container limited to one
CPU runs Serial unless a collector is selected.

### Not supported

| Log | Result |
|---|---|
| ZGC, including Generational ZGC | Rejected with an error that names the collector |
| Shenandoah | Rejected with an error that names the collector |
| Epsilon | Rejected with an error that names the collector, when the log's startup lines name it |
| Eclipse OpenJ9 and IBM Semeru verbose GC logs (`-Xverbosegclog`, XML) | Not recognized as a GC log |
| Java 7 and earlier | Not tested; do not rely on the results |

### Log formats and options

| JDK | Logging | Options that are understood |
|---|---|---|
| Java 8 | `-Xloggc:<file>` with `-XX:+PrintGCDetails`, or `-XX:+PrintGC` alone. Without `-Xloggc`, GC records go to standard output, which Tomcat writes to `catalina.out`. | `-XX:+PrintGCDateStamps`, `-XX:+PrintGCTimeStamps`, `-XX:+UseGCLogFileRotation`, `-XX:+PrintGCApplicationStoppedTime`, `-XX:+PrintHeapAtGC`, `-XX:+PrintTenuringDistribution`, `-XX:+PrintAdaptiveSizePolicy`, `-XX:+PrintCommandLineFlags` |
| JDK 9 and later | Unified logging: `-Xlog:gc*`, or `-Xlog:gc` for less detail | Any decorators (`time`, `utctime`, `uptime`, `uptimemillis`, `uptimenanos`, `timemillis`, `timenanos`, `pid`, `tid`, `level`, `tags`), file rotation (`filecount`, `filesize`), and `safepoint` lines |

A Java 8 log written with `-XX:+PrintGC` alone gives pause times and heap sizes, but it often
does not name the collector and has no generation sizes.

### Recommended logging options

These options give the most complete report. Adjust the path and rotation sizes to suit.

Java 8:

```text
-Xloggc:/path/to/gc.log -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCTimeStamps
-XX:+PrintGCApplicationStoppedTime -XX:+PrintCommandLineFlags
-XX:+UseGCLogFileRotation -XX:NumberOfGCLogFiles=10 -XX:GCLogFileSize=50M
```

JDK 9 and later:

```text
-Xlog:gc*,safepoint:file=/path/to/gc.log:time,uptime,level,tags:filecount=10,filesize=50m
```

- Datestamps (`-XX:+PrintGCDateStamps` or the `time` decorator) give each pause a clock time,
  which time windows and event export need.
- Stopped-time and safepoint lines show application stops that are not GC pauses.
- `-XX:+PrintCommandLineFlags` records the maximum heap and marks each JVM start.
- On Java 8, `-XX:+PrintHeapAtGC` adds the survivor-space occupancy needed to detect premature
  promotion.

## Supplying logs

- **One JVM at a time.** Supply the log files of one JVM, including its rotated files. Analyze
  files from different collectors or different JVMs separately.
- **Compressed files.** Gzip-compressed files, such as `gc.log.3.gz`, are read directly.
- **Large files.** Files are read line by line and are never held in memory, so memory use
  depends on the number of GC pauses, not on the file size. A multi-gigabyte `catalina.out` is
  fine.
- **Startup lines.** Keep the JVM startup lines at the top of the log when you can. They record
  the maximum heap and the JVM configuration that several findings depend on.
- **Clock time.** Logs with datestamps and logs with only JVM uptime are both supported. A time
  window or an event export needs clock time: use a log with datestamps, or supply the JVM start
  time with `--jvm-start`.

### Tomcat `catalina.out`

Without `-Xloggc`, Java 8 writes GC records to standard output, which Tomcat sends to
`catalina.out`. Analyze that file directly: application lines are ignored, including text that
another thread wrote into the middle of a GC record.

Such a split record is recovered only when it has a datestamp (`-XX:+PrintGCDateStamps`). With
uptime alone, the start of the record cannot be told apart from digits the application wrote,
so the record is reported as not parsed rather than given a guessed time.

## Common tasks

### Save the report

Write the full report as Markdown, as well as showing it in the terminal:

```sh
gc-analyze analyze gc.log --output gc-report.md
```

Write a short Markdown summary (at most about 5 KB) for an incident record:

```sh
gc-analyze analyze gc.log --brief --output gc-brief.md
```

Without `--output`, `--brief` writes the summary to standard output.

Write the report as JSON for scripts and dashboards:

```sh
gc-analyze analyze gc.log --json gc-report.json
gc-analyze analyze gc.log --json - | jq .status
```

The JSON holds the status, exit code, diagnosis, findings, all summary figures, the JVM runs,
and the parsing coverage. Each percentage sits next to a field that names what it is a
percentage of, such as `heap.max_heap_source`. `schema_version` changes whenever the layout
changes. With `--json -`, only the JSON goes to standard output; status messages go to standard
error.

The terminal, Markdown, brief, and JSON reports all come from the same analysis, so they always
agree. Output files are replaced in one step, so a reader never sees a half-written file. The
destination directory must already exist.

### Analyze rotated files and JVM restarts

Pass rotated files together, in any order. They are ordered by the times they record:

```sh
gc-analyze analyze gc.log.0 gc.log.1 gc.log.2.current
```

Rotated files of one JVM stay one run, including Java 8 files that repeat the JVM startup lines
at the top of each file. A new JVM run starts when:

- the uptime goes back to zero,
- the process id changes (unified logs with both the `pid` and `tid` decorators), or
- JVM startup lines appear between two pauses.

Each JVM run becomes a numbered **segment**, listed in the **JVM Runs Found** table. Only the
latest run is analyzed unless you choose another:

```sh
gc-analyze analyze gc.log --segment 1
gc-analyze analyze gc.log --segment all
```

With `--segment all`, rates use the combined time of all runs, heap limits are shown for each
run, and the retention trend uses the latest run. Runs logged with uptime only cannot be placed
on one time line, so the timeline and the worst-period figures are left out for them.

### Investigate a time window

Give the window in ISO 8601, preferably with a UTC offset:

```sh
gc-analyze analyze gc.log --start 2026-11-10T14:00:00-05:00 --end 2026-11-10T14:30:00-05:00
```

- Either boundary can be used alone.
- With both boundaries, the report also compares the same window 24 hours earlier, when the
  logs reach back that far.
- A time without an offset uses the log's offset. Log datestamps without an offset are read as
  UTC.
- A pause counts if it overlaps the window. Its full duration counts toward percentiles and the
  longest pause; only the part inside the window counts toward the pause share.
- When the log does not cover the whole window, the report shows the period it does cover and
  labels the pause share accordingly. Coverage does not prove that every rotated file or record
  is present.

For a log with uptime only, supply the JVM start time, including its offset:

```sh
gc-analyze analyze gc.log --jvm-start 2026-11-10T08:00:00-05:00
```

### Supply the maximum heap

If the log does not record the maximum heap, supply the JVM's `-Xmx` value. Without it, heap
percentages use the committed heap.

```sh
gc-analyze analyze gc.log --max-heap 4g
```

### Change the limits

The default `server` workload uses pause limits for applications that serve requests. Use
`batch` where longer pauses are acceptable:

```sh
gc-analyze analyze gc.log --workload batch
```

| Pause measure | `server` warning / critical | `batch` warning / critical |
|---|---|---|
| Any single GC pause or other safepoint stop | ≥ 5 s / ≥ 30 s | ≥ 60 s / ≥ 300 s |
| P99 GC pause | > 1 s / > 5 s | > 5 s / > 10 s |

A P99 warning needs at least 100 pauses. Each kind of pause with at least 100 samples is also
checked on its own, so many short pauses cannot hide a slower kind.

The other limits are in the [option reference](#option-reference).

### Export pauses for a timeline

```sh
gc-analyze analyze gc.log --export-events gc.events.jsonl --host app-03
```

The export holds one JSON object per analyzed pause. It needs clock time: add `--jvm-start` for
a log with uptime only. It can be combined with `--output` and with a time window or segment.

| Field | Content |
|---|---|
| `ts` | The time the log gave the pause, in UTC: its start in Java 8 logs, its end in unified logs |
| `duration_ms` | Pause duration in milliseconds |
| `level` | `WARN` for heap-pressure Full GCs and collection failures, `INFO` otherwise. It is independent of the report's status. |
| `attrs` | Pause kind, cause, heap sizes in KB, JVM uptime, segment number, pause start and end in UTC, and any failure flags |
| `ts_raw`, `tz_source` | The timestamp as logged, and where its time zone came from |
| `host`, source file and line, message | Where the pause came from, and a readable summary |

## Option reference

Run `gc-analyze analyze --help` for the same list.

| Option | Purpose | Default |
|---|---|---|
| `--output`, `-o` FILE | Write the report as Markdown | |
| `--brief` | Write a short Markdown summary instead of the full report | |
| `--json` FILE | Write the report as JSON (`-` for standard output) | |
| `--export-events` FILE | Write one JSON line per pause | |
| `--host` NAME | Host name to put in exported events | |
| `--start`, `--end` TIME | Analyze only this time window (ISO 8601) | whole log |
| `--segment` RUN | JVM run to analyze: `latest`, `all`, or a run number | `latest` |
| `--jvm-start` TIME | JVM start time, for logs with uptime only | |
| `--max-heap` SIZE | Maximum heap when the log does not record it, such as `4g` | from the log |
| `--workload` NAME | Pause limits: `server` or `batch` | `server` |
| `--heap-warning` PERCENT | Occupancy right after a Full GC (or comparable collection) that warns | `80` |
| `--heap-critical` PERCENT | Occupancy right after a Full GC (or comparable collection) that is critical | `95` |
| `--full-gc-streak` COUNT | Heap-pressure Full GCs within 5 minutes that make a streak finding | `3` |
| `--min-rate-window` MINUTES | Log length needed before per-hour rates and rate warnings are shown | `60` |
| `--verbose`, `-v` | Show parsing details for each file | |
| `--profile` | Show where the analysis spent its time | |
| `--profile-output` FILE | Save the profiling data to a file | |

## Understand the report

Sections appear only when the log holds the data they need. Each finding has a severity,
evidence, a confidence, and a suggested action with a documentation reference. Advice follows
the JDK in the log: a Java 8 log gets Java 8 documentation and only flags that Java 8 accepts.

| Report item | Meaning |
|---|---|
| **Status** | The most severe finding. The summary also lists measurements the log could not provide. |
| **Pauses** | Stop-the-world collections and GC phases by kind, such as Young, Mixed, Full, or Remark. |
| **P50 / P95 / P99** | Pause durations at the 50th, 95th, and 99th percentiles. P50 is the median; P99 shows the slow end. Check the sample count and the longest pause too. |
| **Time in GC pauses / pause share** | Time spent in logged GC pauses, and its share of the time basis named in the summary. |
| **Worst 1, 5, and 15 minutes** | The stretches with the highest pause share, which show incidents that an average over the whole log hides. |
| **Heap after GC** | Memory in use after a collection. After a young collection, this can include old garbage that has not been collected yet. |
| **Highest post-Full-GC occupancy** | Memory in use right after a Full GC, as a share of that run's maximum heap when known. |
| **Full GC streaks** | Heap-pressure Full GCs back to back (3 within 5 minutes by default). A warning when each still frees memory; critical ("memory thrashing") when they free little and leave the heap nearly full. A streak only during JVM start-up (the first 10 minutes of uptime) is information. |
| **Full GC causes** | Heap pressure, explicit requests, metaspace, other known triggers, or unknown. Only heap-pressure causes count toward heap-pressure rates and streaks. |
| **Post-GC occupancy trend** | Comparable post-collection samples in one JVM run. A sustained rise is a reason to look at what the application retains. |
| **Safepoint timing** | Time to reach safepoints and time spent at them, where logged, with stops that were not GC pauses. |
| **Timeline** | Pauses, time paused, longest pause, Full GCs, and heap in equal time slices. |
| **Data Notes / Parsing Coverage** | Missing measurements, assumptions, and GC lines that were not understood. Coverage describes every supplied file, even when a segment or window is selected. |

- Without a time window, the time basis runs from the start of the first pause to the end of
  the last.
- Per-hour rates need at least 60 minutes of log by default; shorter logs show counts instead.
- Heap percentages use the maximum heap when known and the committed heap otherwise; the report
  names which. Old-generation percentages use the old generation's capacity where it is logged.
- Pauses whose logged sizes contradict each other, such as heap after GC above the committed
  heap, are counted under **Data limits** and left out of heap figures. Their pause times still
  count.

### Interpret the retention assessment

The retention trend compares like with like within one JVM run: memory in use after Full GCs,
after completed G1 mixed collections, or in the old generation after CMS sweeps. It needs at
least three samples over at least an hour, with one in the middle third of that period. The
first 10 minutes of uptime are left out.

- Samples after G1 mixed collections and CMS sweeps can include objects that are no longer
  used. A G1 mixed sequence cut off by the end of the log is marked unconfirmed.
- Heap after a young collection is only an upper bound on the memory in use, so it never
  establishes a trend on its own.
- With G1 region counts, the samples measure the space taken by occupied regions.

A sustained rise or a sudden step is evidence to compare with load, deployments, caches, and
retained objects. High occupancy after Full GCs can show heap pressure even when there are too
few samples for a trend.

## Exit codes

The exit codes follow the convention used by monitoring checks (OK, WARNING, CRITICAL, UNKNOWN),
so a monitoring system can run `gc-analyze` as a check.

| Code | Meaning |
|---|---|
| `0` | The analysis found nothing that needs attention. Informational findings may be present. |
| `1` | A warning finding, or more than 1% of the GC lines were not understood. |
| `2` | A critical finding. |
| `3` | The log could not be analyzed: a command-line error, a missing, unreadable, or unsupported log, or an output file that could not be written. |

Reports and exports are written before the command exits with `1` or `2`, so a script should
keep the exit code and read the report.

## Troubleshooting

| Problem | What to check |
|---|---|
| `gc-analyze` is not found | Run `uv tool update-shell`, then open a new terminal. |
| `uv` is not found | Open a new terminal, then follow the PATH instructions from the uv installer. |
| Unsupported format, or no usable GC events | Check that the file is an uncompressed or gzip-compressed text GC log from a collector and JDK in [Supported Java versions and collectors](#supported-java-versions-and-collectors). The error shows samples of lines that were not understood. |
| Incomplete parse | Review **Parsing Coverage** and its sample lines; missing records can change counts and conclusions. Use `--verbose` for details on each file. |
| A time window or export needs clock time | Supply `--jvm-start` with the JVM's start time and UTC offset, or use a log with datestamps. |
| Heap percentages use the committed heap | Supply the maximum heap with `--max-heap`, or include the JVM startup lines that record it. |
| The retention trend is not assessed | **Data Notes** and **Post-GC occupancy trend** show which samples were available and why they were not enough. |

## How accuracy is verified

Besides tests with sample logs, the maintainer's test suite includes logs written by real
Eclipse Temurin JVMs on Linux. For each run, the JVM also recorded every collection it performed
and the memory its threads allocated. The tests check the analyzer's pause counts, Full GC
causes, JVM runs, maximum heap, and allocation rate against that record.

| JDK | Collectors run |
|---|---|
| Java 8 | G1, Parallel, Parallel with Serial Old, CMS, Serial, ParNew with Serial Old |
| JDK 11 | G1, Parallel, Parallel with Serial Old, CMS, Serial |
| JDK 17, 21, 25 | G1, Parallel, Serial |

The runs also cover:

- **Java 8 logging:** `PrintGC`-only logs, rotated files, and GC output mixed into `catalina.out`.
- **CMS under stress:** concurrent mode failures, promotion failures, and young collections
  that escalated to Full GCs.
- **Unified logging:** several decorator sets and rotated files.
- **Other cases:** two JVM runs in one file, logs cut off mid-record, and a ZGC log, which is
  rejected.

JDKs 9, 10, 12 to 16, 18 to 20, and 22 to 24 use the same unified logging and are supported,
but their logs were not part of these tests.
