# gc-analyze: remaining work

What is still open after v6.0.0 (implemented 2026-11-16, not yet committed). Completed items
were removed; item numbers are kept so they match earlier reviews and commit messages.

## 1. Confirm with real logs

The code for these is written and tested, but only against hand-written logs.

| # | Item | What is needed |
|---|---|---|
| D10 | JDK 13+ safepoint lines (`Safepoint "<op>", ... Reaching safepoint: N ns, ... Total: N ns`) | The pattern follows `SafepointTracing::end` in jdk13u, jdk17u, jdk21u and mainline. Run the tool on one real JDK 17 or 21 log written with `-Xlog:gc*,safepoint` and check that the safepoint count matches `scripts/crosscheck.py` and that stops not explained by GC look right. |
| D11 | Decimal-comma logs (`0,0301 secs`, `10,500ms`) | One real log from a JVM running under a decimal-comma locale. `scripts/crosscheck.py` does not read these; check the totals by hand. |
| V1 | Collectors and set-ups only seen in synthetic logs | CMS and Serial on real logs, unified CMS (`-Xlog:gc*` with `-XX:+UseConcMarkSweepGC`, JDK 9-13), and rotated multi-file input from one real JVM. |
| V2 | Golden values | Confirm the hand-computed `tests/fixtures/*.expected.json`. One changed in v6.0.0: `g1unified_time` floor slope 43.77408 → 43.76307 MB/h (Theil-Sen, the median of the pairwise slopes 32.92, 43.76 and 54.54). |

## 2. Formats not supported

| # | Item | Detail |
|---|---|---|
| U9 | ZGC and Shenandoah | Rejected outright; both are common on large heaps. Needs real sample logs of each. |
| U10 | Other gaps | Premature promotion beyond Java 8 `-XX:+PrintHeapAtGC`; start-up detection without uptime; unified CMS concurrent mode failure; Java 8 G1 whole-cycle concurrent time. Needs real samples of each format. |

## 3. Thresholds

| # | Item | Detail |
|---|---|---|
| S8 | Thresholds not configurable | `--workload server\|batch` covers the pause limits. Still internal to `DiagnosticThresholds`: worst-5-minute share (25/50%), ineffective Full GC (< 20% freed, > 80% full), warm-up (10 min), step change (2× median, 10% of capacity), CPU split, concurrent share (25%), survivor overflow (99%, 3 collections), trend test (p < 0.05, ≥ 5% of capacity), humongous (10% of heap, 20% of allocation). Decide which are worth exposing as options. |

## 4. Advice

| # | Item | Detail |
|---|---|---|
| A5 | Release coverage | G1 entries are checked against the JDK 17 and 21 guides; the JDK 11 guide pages no longer resolve. Still unverified and left out: the pre-JDK 17 `ParallelRefProcEnabled` default, CMS promotion-failure advice, `DisableExplicitGC` versus direct buffers. |
| A6 | Tomcat-specific advice | Done: proxy and health-check wording on long pauses; the `gcDaemonProtection` note for evenly spaced `System.gc()` on Java 8. Open: session replication, and tying long pauses to connector timeouts with Tomcat's documented defaults. Check each against the Tomcat documentation first. |

## 5. Owner decisions still open

| # | Decision | Notes |
|---|---|---|
| O5 | Where tests live | `tests/` is gitignored, so every regression test (including `tests/test_plan_v6.py`) exists on one machine. Nothing is protected until that changes. |

## 6. Integration

- `scripts/crosscheck.py`: add survivor occupancy and the allocation rate (counts, pause totals,
  heap sums, last old gen, last metaspace and safepoint counts are already checked).
- Real-shaped fixtures for JDK 17 and 21 G1; none exist.
- `--export-events`: add pause start and end, CPU times, survivor occupancy, warning codes.
- `--json` summary with findings and warning codes.
- A `--findings-only` view.
- Whole files are read into memory; not measured on multi-gigabyte logs.
- The deprecation policy `AGENTS.md` requires is not documented.

## 7. Prompt for the next session

```text
Work through plan.md (repository root) for gc-analyze. Read plan.md and AGENTS.md in full
first. Goal: the report must be something an operator can trust when diagnosing a Java
application server (Tomcat); a wrong alarm and a missed alarm are both defects.

1. Post a short bullet plan before changing code.
2. Write a failing regression test first (inline hand-written logs in tests/), then fix.
   Do not weaken an existing test; if an expectation is wrong, say which and why.
3. For anything that depends on JVM or Tomcat behaviour, read the primary source first and
   cite it in advice.py or a code comment. If you cannot read it, leave the item out.
4. Run the full verification sequence from AGENTS.md, re-run the tool on test-logs/ and
   scripts/crosscheck.py, and report every change in status, exit code and numbers.
5. Remove items from plan.md when they are done.

Repository rules:
- Files under src/gc_analyze/ except __init__.py are committed with CRLF line endings. Keep
  them CRLF and confirm with `git diff --stat` that only intended lines changed.
- test-logs/ holds real production logs. Never commit, publish or quote them, and never put
  host names or raw lines from them in code, tests, fixtures, plan.md or the README.
- tests/ is gitignored and maintainer-local. Never `git add -f` it.
- ruff and basedpyright are in the dev extra: `uv run --frozen --extra dev ...`.
- Python 3.15 only; uv only; pip-audit through uv.
- The shell is zsh with noclobber: use `>|` to overwrite a file.
- Do not commit or push unless asked.

Stop and ask, rather than guessing, when an item needs a log format you have no real example
of; say which sample log you need.
```
