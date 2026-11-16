# gc-analyze: plan to make the output correct and useful

Review date 2026-11-15, against v5.0.0 (commit `7471a25`). Replaces the previous `plan.md`;
every item from it that is still open is carried into the sections below and marked
*(carried over)*.

## 1. Verdict

**The arithmetic is right. The conclusions drawn from it are not yet reliable.**

What was checked, and how:

- The three real logs in `test-logs/` (two JDK 11 G1, one Java 8 Parallel with a 512 GB heap)
  were re-parsed with separate throw-away scripts that share no code with the tool. Pause
  counts, total pause time, P50/P95/P99/max, overhead, window length, allocation rate,
  promotion totals, old-gen capacity, the last floor and the metaspace figures all match the
  report exactly. Parsing coverage is 100% of complete records on all three.
- The 338 local tests pass.
- GC cause names were compared with `GCCause::to_string` in OpenJDK (jdk8u and mainline).
- Six synthetic logs were written to probe the judgement layer (status, severity, findings).
  This is where the defects are: section 2.

Not checked: CMS and Serial on real logs (fixtures only), unified CMS, ZGC/Shenandoah
(rejected by design), multi-file rotation on real data. Python 3.15 is the only supported Python version.

## 2. Confirmed defects (each reproduced)

Ordered by how badly they mislead the reader.

| # | Defect | Reproduction | Fix |
|---|---|---|---|
| D1 | **A single long freeze is not an alarm.** Warnings are driven by P99, the worst-5-minute share (> 25%) and the Full GC rate (> 1/h). One long stop passes under all three. `pause_extreme_seconds` exists in `DiagnosticThresholds` and is never read. | 48 h of healthy young GCs plus one 60 s Full GC: Status `STABLE`, exit code 0, one `[INFO]` finding. | Add warnings on the longest pause and on counts over absolute limits (proposed: any pause ≥ 5 s WARNING, ≥ 30 s CRITICAL; see decision O2). |
| D2 | **Status and exit code disagree with the findings.** Both are computed from `summary.warnings`; findings that have no health warning behind them (growing live set, log ends mid-collection) do not count. | Floor rising +9.9 MB/h, r² 0.85, 143 floors, live set doubled in 71 h: finding is `[WARNING]`, confidence high, yet Status `STABLE`, exit 0, "Leak risk: Low". | One source of truth: derive status and exit code from the findings list. |
| D3 | **False CRITICAL from half-versus-half comparisons.** `full_gc_accelerating` needs only 3 intervals and `reclamation_declining` only 4 Full GCs; each alone is CRITICAL. Reclamation is compared in absolute KB, which depends on how much garbage happened to be there. | Four healthy Full GCs (each frees 56%) with gaps of 10 h, 6 h, 6.5 h: `UNSTABLE - INTERVENTION REQUIRED`, exit 2, titled "Heap-pressure Full GCs are frequent" at 0.10/h. | Demote both to supporting evidence unless an independent signal agrees (rate, streak, ineffective Full GC, high floor). Require ≥ 6 Full GCs and a monotonic-trend test; compare % freed, not KB. |
| D4 | **Promotion failures on Parallel and Serial are parsed, then dropped.** The count is only reported through `cms_metrics`, which is built for CMS logs only. | Parallel log with 11 `--[PSYoungGen` promotion failures: no warning, no finding; visible only as a suffix in the Top 10 table. | Report promotion failure for every generational collector. |
| D5 | **GC cause names do not match HotSpot.** `"JvmtiEnv ForceGarbageCollector"` should be `"JvmtiEnv ForceGarbageCollection"`; `"Full GC Alot"` should be `"FullGCAlot"`. Missing non-heap causes: `G1 Periodic Collection`, `Allocation Profiler`, `CodeCache GC Threshold`, `CodeCache GC Aggressive`. | Hourly Full GCs forced by a JVMTI agent (monitoring/profiling tools do this) are counted as "heap-pressure Full GCs 0.92 per hour". | Correct the strings; add the missing causes; add a test that pins the list to the OpenJDK source. |
| D6 | **The G1 humongous finding blames the wrong thing.** On the large real G1 log all 2,265 "G1 Humongous Allocation" pauses are Concurrent Start pauses. G1 checks the marking threshold at every humongous allocation and starts marking if occupancy is already over it (G1 tuning guide), so the cause names the moment the threshold was noticed, not the reason it was exceeded. Humongous allocation there is 0.11 MB/s of 4.4 MB/s, and humongous regions hold under 1% of the heap. The real picture: live old gen is about 66% of max heap, marking starts at a median 73% occupancy, so 2,478 marking cycles run (one every 3 min), each followed by one mixed GC freeing about 4%. Raising the region size, as advised, would not stop them. The 18% share also divides by all pauses including Remark and Cleanup (it is 43% of young pauses, 91% of marking cycles). | Real log, findings panel. | Separate "marking started by a humongous allocation" from "humongous objects fill the heap", using the humongous region counts the parser already reads. Add a finding for marking that runs back-to-back because the live set sits at the threshold, with the heap-size remedy. |
| D7 | **Wording and layout errors in otherwise correct output.** (a) "P99 0.0 s" for 0.020 s; (b) "The 10 longest are mostly Young pauses" printed beside a 60 s Full GC; (c) "Back-to-back Full GCs are freeing little memory" as the title for a single Full GC; (d) `--brief` cuts the Live set line mid-number ("245.29 G"); (e) at 80 columns the Top 10 table truncates the two fields that matter, time and cause ("2026-01-0…", "Ergonomi…"); (f) for Java 8 logs the window's end time is the *start* of the last pause (146 s early on the real Parallel log; the duration is right); (g) "Heap-pressure Full GCs" appears twice in a row in the summary. | Real and synthetic logs. | Fix each; add an 80-column rendering test. |

## 3. Statistics and thresholds

| # | Item | Detail |
|---|---|---|
| S1 | Trend test *(carried over, now high priority)* | The floor trend is gated on r² ≥ 0.5. r² measures scatter, not whether a trend exists: three floors fit a line easily, while a slow leak under a noisy sawtooth fails. Replace with a Theil–Sen slope and a Mann–Kendall test, and judge by effect size (projected growth as % of capacity). The large real G1 log is a good control: +0.3 MB/h over 2,457 floors is statistically real but only +1.3% of the heap in 127 h, so "no meaningful growth" is the right answer for the right reason. |
| S2 | Leak score *(carried over; decision O1)* | Replace the additive 0–100 score with a verdict plus evidence. Two results show why: the Parallel log, whose JVM ended in continuous Full GCs at 97% old gen, scores "Medium 55"; a textbook linear leak scores "Low 35". |
| S3 | Small samples | P99 is labelled "1-in-100 pauses" even when there are fewer than 100 pauses. Show the sample size and drop the phrase below 100. |
| S4 | Defaults suit batch work, not a request-serving JVM *(decision O2)* | A P99 pause is "within normal range" up to 1 s and only a warning above 5 s; overhead is "healthy" up to 5%. For Tomcat behind a load balancer, pauses of a few seconds already fail health checks and time out requests. |
| S5 | G1 promotion figure | Uses the change in old + humongous regions across a young GC; humongous regions reclaimed in the same pause cancel real promotion. Use the Old region count alone. |
| S6 | G1 allocation rate *(resolves a carried-over item)* | For G1 use the whole-heap basis, which includes humongous allocation (4.42 vs 4.27 MB/s on the real log), instead of labelling the young-only figure. |
| S7 | Start-up context for one-off events | The single evacuation failure on the real G1 log happened 227 s after start while the committed heap was still growing from 1 GB to 3 GB. It is reported as a plain WARNING and sets the status to DEGRADED for a five-day window. Mark events inside the warm-up period, and report that `-Xms` is below `-Xmx` when the committed heap grows (this log shows it; the tool does not say it). |
| S8 | Thresholds not configurable *(carried over)* | Worst-5-minute share (25/50%), ineffective Full GC (< 20% freed, > 80% full), warm-up (10 min), step change (2× median, 10% of capacity), CPU split, concurrent share (25%), survivor overflow (99%, 3 collections). Confirm, then expose the ones worth tuning. |
| S9 | Trends across JVM runs *(carried over)* | With `--segment all`, floors and trends mix the runs. |

## 4. Signals in the log that the tool does not use

| # | Signal | Why it helps |
|---|---|---|
| U1 | `MMU target violated` (24 lines in the real G1 log) | G1 itself saying it missed the pause-time goal. |
| U2 | Humongous region counts (already parsed) | Humongous occupancy and allocation rate; needed for D6. |
| U3 | Total stopped time minus GC pause time | The safepoint section prints the total only. The difference is time frozen for reasons other than GC, which heap tuning cannot fix. |
| U4 | Safepoint lines on JDK 13+ *(carried over)* | Only the Java 8 / JDK 9–12 "Total time for which application threads were stopped" line is read. |
| U5 | user ÷ real per pause | Effective GC parallelism. On the real Parallel log the Full GCs ran at about 11× on 32 GC threads, and some early young GCs spent more time in the kernel than collecting. |
| U6 | What happened last | The real Parallel log's unfinished final record starts 4.6 s after the previous 146 s Full GC ended. The finding should say the JVM was in continuous Full GC when the log stops, not only that the record is incomplete. |
| U7 | `gc,init` on JDK 17+: initial/min heap, worker counts | Configuration without `CommandLine flags`. |
| U8 | G1 pause phases and reference processing | The Remark advice tells the reader to "look at the Reference Processing phase", which the tool does not parse. Either parse `gc,phases` / `gc,ref` or name the logging option to turn on. |
| U9 | ZGC and Shenandoah *(carried over)* | Rejected outright; both are common on large heaps. |
| U10 | Other gaps *(carried over)* | Premature promotion beyond Java 8 `PrintHeapAtGC`; start-up detection without uptime; unified CMS concurrent work and concurrent mode failure; Java 8 G1 whole-cycle concurrent time. |

## 5. Advice

| # | Item | Detail |
|---|---|---|
| A1 | Lead with one diagnosis | The real Parallel log yields ten findings, six CRITICAL. Its story is one sentence: the live set jumped from 7 GB to 245 GB in 34 minutes, then climbed to 97% of the old generation, and the JVM spent its last 17 minutes almost entirely in Full GC. Put that sequence first; rank the rest as consequences. |
| A2 | Suppress tuning advice for symptoms | In that same report, survivor sizing, collector choice and metaspace tuning are offered for a JVM that ran out of heap. When a root-cause finding is present, demote the secondary advice. |
| A3 | Scale the heap-dump advice | `jcmd GC.heap_dump` is recommended for a 512 GB heap holding 332 GB live. Above a size limit, recommend `jcmd <pid> GC.class_histogram` first, and mention `-XX:+HeapDumpOnOutOfMemoryError` when the flags show it is already set. |
| A4 | Survivor advice under the Parallel collector | The advice cites `-XX:SurvivorRatio`. With adaptive sizing on (the Parallel default) that flag may not hold. Not yet checked against the documentation: confirm before changing. |
| A5 | Release coverage *(carried over)* | Entries cite the Java 8 and JDK 17 guides; check against 11 and 21. JEP 307 and JEP 423 entries rest on search summaries (HTTP 403). Unverified and left out: pre-JDK 17 `ParallelRefProcEnabled` default, CMS promotion-failure advice, `DisableExplicitGC` versus direct buffers. |
| A6 | Tomcat-specific advice *(carried over)* | Tie findings to what an operator sees: connector and proxy timeouts, health checks, session replication, the JRE memory leak listener. Check each against Tomcat documentation first. |

## 6. Decisions for the owner

| # | Decision | Recommendation |
|---|---|---|
| O1 | Leak score | Replace with a verdict (growing / step change / full but flat / none / not assessed) plus evidence. Changes what triggers exit code 2. |
| O2 | Severity defaults | Adopt request-serving defaults: longest pause ≥ 5 s WARNING, ≥ 30 s CRITICAL; P99 ≥ 1 s WARNING, ≥ 5 s CRITICAL. Keep the current values available as a flag or profile. |
| O3 | Time-to-exhaustion | The tool deliberately does not project. A range ("at this rate the old generation is full in 60–110 h, if growth stays linear") is the first thing an operator asks. Recommend adding it only when the trend test in S1 passes. |
| O4 | Truncated final record *(carried over)* | Keep counting it as unparsed (current behaviour), since a cut-off record and a garbled one cannot be told apart. |
| O5 | Where tests live *(carried over)* | `tests/` is gitignored, so every regression test exists on one machine. Nothing in this plan is protected until that changes. |

## 7. Order of work

1. **Wrong conclusions** — D1, D2, D3, D4, D5. Small, contained changes in `analysis.py`,
   `findings.py`, `report.py`, `cli.py`. Each gets a regression test built from the synthetic
   log that exposed it. Needs O2 for the D1 thresholds.
2. **G1 interpretation and trend statistics** — D6, S1, S2 (needs O1), S5, S6, S7.
3. **Presentation** — D7, S3, A1, A2, A3.
4. **Unused signals** — U1, U2, U3, U5, U6, U7, then U4 and U8.
5. **Advice review** — A4, A5, A6.
6. **Formats and integration** — U9, U10, S8, S9, and section 8.

## 8. Protect and integrate *(all carried over)*

- Run verification on Python 3.15 only; do not maintain a matrix for older Python versions. Use the latest stable compatible dependencies and keep their minimum versions current in `pyproject.toml`, using `uv`.
- Confirm the hand-computed golden `expected.json` values. v5.0.0 behaviour has no golden
  fixtures, only inline logs.
- `pip-audit` 2.10.1 now runs on Python 3.15.2 using `uv run --frozen --extra dev pip-audit`; verified with no known dependency vulnerabilities. Keep auditing on Python 3.15.
- Extend `scripts/crosscheck.py` to old-gen, survivor, metaspace and allocation figures (the
  throw-away scripts used for this review did this by hand).
- Add real-shaped fixtures for JDK 17 and 21 G1; none exist.
- `--export-events`: add pause start and end, CPU times, survivor occupancy, warning codes.
- `--json` summary with findings and warning codes.
- Report length: a `--findings-only` view; revisit the 5 KB limit on `--brief`.
- Whole files are read into memory; not measured on multi-gigabyte logs.
- The deprecation policy `AGENTS.md` requires is not documented.

## 9. Implementation prompt

Paste everything in the block below into a new session started in this repository. Edit the
"Owner decisions" lines first if you want something other than the recommendation.

```text
Implement the plan in plan.md (repository root) for gc-analyze. Read plan.md and AGENTS.md
in full before doing anything else. plan.md is the specification: sections 2 to 5 and 8 list
the work, section 7 gives the order, section 6 lists the owner decisions.

Goal: the report must be something an operator can trust and act on when diagnosing a Java
application server (Tomcat). Correct conclusions matter more than new features. A wrong
alarm and a missed alarm are both defects.

Owner decisions (section 6 of plan.md). Treat these as settled:
- O1 leak score: replace the 0-100 score with a categorical verdict plus evidence.
- O2 severity defaults: longest pause >= 5 s WARNING, >= 30 s CRITICAL; P99 >= 1 s WARNING,
  >= 5 s CRITICAL. Keep the old values reachable through a flag or profile.
- O3 time-to-exhaustion: add it as a range, shown only when the new trend test passes.
- O4 truncated final record: keep counting it as unparsed.
- O5 tests: leave tests/ gitignored; do not git add it.

Work in the order of section 7, one phase at a time:
1. Before each phase, post a short bullet plan of the changes you will make.
2. For every defect (D1-D7), first write a regression test that fails for the reason the
   plan describes, using a small hand-written inline log in
   tests/test_output_correctness.py. Then fix the code and show the test passing. Do not
   weaken or delete an existing test to make a change pass; if an existing expectation is
   wrong, say which one and why before changing it.
3. For statistics items (S1-S9), state the formula you are implementing and check it against
   a hand-computed example in the test.
4. For anything that depends on JVM or Tomcat behaviour (GC cause names, flag semantics,
   defaults by release, advice text), read the primary source first (OpenJDK source, the
   HotSpot GC tuning guide for the relevant release, Tomcat documentation) and cite it in
   advice.py or a code comment. If you cannot read the source, leave the item out and report
   it; do not write advice from memory. Items A4 and A5 are explicitly unverified.
5. After each phase run the full verification sequence from AGENTS.md and re-run the tool on
   the three logs in test-logs/. Compare the before and after reports and tell me every
   change in status, exit code, findings and numbers, and whether each change is intended.
6. Extend scripts/crosscheck.py as section 8 describes, and run it on the real logs at the
   end of every phase. Any number that differs from the independent tally is a blocker.
7. Update plan.md as you go: mark each item done, partly done (say what is left) or not
   done (say why). Do not delete items.

Repository rules that have caused problems before:
- Files under src/gc_analyze/ except __init__.py are committed with CRLF line endings. Keep
  them CRLF and confirm with `git diff --stat` that only the lines you meant to change
  changed.
- test-logs/ holds real production logs. Never commit, publish or quote them, and never put
  host names or raw lines from them in code, tests, fixtures, plan.md or the README.
- tests/ is gitignored and maintainer-local. Never `git add -f` it.
- ruff and basedpyright are in the dev extra: `uv run --frozen --extra dev ...`.
- Use Python 3.15 only and the latest stable compatible dependencies, managed exclusively with uv.
- Run pip-audit through uv on Python 3.15; if it cannot start, use osv-scanner or report the
  blocker, and say which. Do not use an older Python.
- The shell is zsh with noclobber: use `>|` to overwrite a file.
- Keep edits minimal. Do not change the public CLI options, exit-code meanings or file
  layout beyond what plan.md calls for; where the plan does change them (O1, O2, D2), list
  each change for the README and propose the version number under semantic versioning.
- Do not commit or push. Stop after each phase and give me a summary; I will tell you when
  to continue.

Stop and ask me, rather than guessing, if: a fix would contradict an owner decision above; a
real-log number changes and you cannot explain why; a primary source contradicts the plan;
or an item turns out to need a format you have no real example of (JDK 13+ safepoint lines,
ZGC, Shenandoah, unified CMS). For those formats, tell me what sample log you need.

When every phase is finished, give me: the list of plan items with their final state, the
before/after status and exit code for each real log, anything you could not verify, and the
README sections that need updating.
```
