"""Typer command-line interface."""

from __future__ import annotations

import cProfile
import pstats
import sys
from io import StringIO
from pathlib import Path
from typing import Annotated

import typer

from .coverage import UNPARSED_WARNING_THRESHOLD_PCT
from .export import ExportError, export_events
from .findings import build_findings, overall_status
from .jvm_config import parse_size_argument
from .markdown import render_brief_markdown, render_markdown
from .models import DiagnosticThresholds, Finding
from .pipeline import NoEventsError, parse_time_option, run_analysis
from .report import ReportContext, build_sections, console, render_rich

__version__ = "6.0.0"

app = typer.Typer(
    name="gc-analyze",
    help="JVM GC log analyzer: G1, Parallel, CMS and Serial; Java 8 and unified (JDK 9+) logs",
    add_completion=False,
    rich_markup_mode="rich",
)


def exit_code(findings: list[Finding], unparsed_pct: float) -> int:
    """0 clean, 1 warning findings or incomplete parse, 2 critical findings.

    The same findings the report lists decide the code: informational findings do not count.
    """
    status = overall_status(findings)
    if status == "critical":
        return 2
    if status == "warning" or unparsed_pct > UNPARSED_WARNING_THRESHOLD_PCT:
        return 1
    return 0


@app.command()
def analyze(
    log_files: Annotated[
        list[Path],
        typer.Argument(
            help="GC log file(s). Rotated files (gc.log.0, gc.log.1, ...) are ordered by time.",
            exists=True,
            file_okay=True,
            dir_okay=False,
            readable=True,
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report as Markdown to this file"),
    ] = None,
    brief: Annotated[
        bool,
        typer.Option(
            "--brief",
            help="Case-file summary (<= ~5 KB Markdown): to --output, or stdout without it",
        ),
    ] = False,
    export_events_path: Annotated[
        Path | None,
        typer.Option(
            "--export-events",
            help="Write one JSON line per GC pause (shared events.jsonl format)",
        ),
    ] = None,
    host: Annotated[
        str | None, typer.Option("--host", help="Host name to put in exported events")
    ] = None,
    start: Annotated[
        str | None,
        typer.Option("--start", help="Analyze from this time (ISO 8601; log's offset if none)"),
    ] = None,
    end: Annotated[
        str | None,
        typer.Option("--end", help="Analyze up to this time (ISO 8601; log's offset if none)"),
    ] = None,
    segment: Annotated[
        str,
        typer.Option(
            "--segment", help="JVM run to analyze when the input spans restarts: latest, all, or N"
        ),
    ] = "latest",
    jvm_start: Annotated[
        str | None,
        typer.Option(
            "--jvm-start",
            help=(
                "JVM start time (ISO 8601 with offset, e.g. 2026-11-10T14:00:00-05:00) to turn "
                "uptime into wall-clock time for logs without datestamps"
            ),
        ),
    ] = None,
    max_heap: Annotated[
        str | None,
        typer.Option("--max-heap", help="Max heap (-Xmx) when the log doesn't state it, e.g. 4g"),
    ] = None,
    min_rate_window: Annotated[
        float,
        typer.Option(
            "--min-rate-window",
            help="Minutes of log needed before per-hour rates and rate warnings are shown",
            min=0.0,
        ),
    ] = 60.0,
    full_gc_streak: Annotated[
        int,
        typer.Option(
            "--full-gc-streak",
            help="Back-to-back heap-pressure Full GCs (within 5 minutes) that count as thrashing",
            min=2,
        ),
    ] = 3,
    heap_warning: Annotated[
        float,
        typer.Option(
            "--heap-warning", help="Heap-after-GC % that triggers a warning", min=0.0, max=100.0
        ),
    ] = 80.0,
    heap_critical: Annotated[
        float,
        typer.Option(
            "--heap-critical", help="Heap-after-GC % that is critical", min=0.0, max=100.0
        ),
    ] = 95.0,
    workload: Annotated[
        str,
        typer.Option(
            "--workload",
            help=(
                "Pause limits to judge by: server (request-serving; any pause >= 5 s warns, "
                ">= 30 s is critical, P99 > 1 s warns) or batch (throughput first; P99 > 5 s "
                "warns, a single pause only from 60 s)"
            ),
        ),
    ] = "server",
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show parsing details")] = False,
    profile: Annotated[bool, typer.Option("--profile", help="Show profiling statistics")] = False,
    profile_output: Annotated[
        Path | None, typer.Option("--profile-output", help="Save profiling data to this file")
    ] = None,
) -> None:
    """Analyze JVM GC log file(s).

    Exit codes: 0 = clean, 1 = warning findings or incomplete parse, 2 = critical findings.
    """
    profiler = cProfile.Profile() if profile else None
    if profiler:
        profiler.enable()

    try:
        jvm_start_dt = parse_time_option(jvm_start, "--jvm-start", None)
        max_heap_bytes = parse_size_argument(max_heap) if max_heap else None
        thresholds = DiagnosticThresholds.for_workload(workload).model_copy(
            update={
                "heap_warning_percentage": heap_warning,
                "heap_critical_percentage": heap_critical,
                "min_rate_window_hours": min_rate_window / 60,
                "full_gc_streak_count": full_gc_streak,
            }
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc

    try:
        try:
            result = run_analysis(
                log_files,
                thresholds=thresholds,
                jvm_start=jvm_start_dt,
                max_heap_bytes=max_heap_bytes,
                segment=segment,
                start=start,
                end=end,
            )
        except NoEventsError as exc:
            console.print(f"[critical]ERROR: {exc}[/critical]")
            console.print(
                f"[critical]{exc.coverage.candidate_lines} GC event lines found, "
                f"{exc.coverage.parsed_candidate_lines} parsed.[/critical]"
            )
            for sample in exc.coverage.unparsed_samples:
                console.print(f"  Unparsed sample {sample}", markup=False, highlight=False)
            sys.exit(1)
        if verbose:
            for f in result.files:
                console.print(
                    f"[info]{f.path}: {f.parser.gc_type_name} ({f.parser.log_family}), "
                    f"{len(f.lines)} lines, {len(f.events)} pauses[/info]"
                )
        summary = result.summary
        ctx = ReportContext(
            summary=summary,
            gc_type=result.gc_type,
            events=result.events,
            coverage=result.coverage,
            file_coverages=result.file_coverages,
            segments=result.segments,
            segment_label=result.segment_label,
            window_label=result.window_label,
            comparison=result.comparison,
            comparison_label=result.comparison_label,
            inputs=[str(f.path) for f in result.files],
            findings=build_findings(summary, result.gc_type, result.events, result.coverage),
        )
        sections = build_sections(ctx)

        if brief and output is None:
            sys.stdout.write(render_brief_markdown(sections))
        else:
            render_rich(sections)
        if output is not None:
            text = render_brief_markdown(sections) if brief else render_markdown(sections)
            output.write_text(text, encoding="utf-8")
            console.print(f"\n[success]✓ Summary exported to {output}[/success]")
        if export_events_path is not None:
            max_heap_kb = summary.heap.max_heap_kb if summary.heap.max_heap_known else None
            written = export_events(
                ctx.events, export_events_path, host=host, max_heap_kb=max_heap_kb
            )
            console.print(f"[success]✓ {written} events exported to {export_events_path}[/success]")

        if profiler:
            profiler.disable()
            if profile_output:
                profiler.dump_stats(str(profile_output))
                console.print(f"\n[info]Profiling data saved to {profile_output}[/info]")
            stream = StringIO()
            stats = pstats.Stats(profiler, stream=stream)
            stats.strip_dirs().sort_stats("cumulative").print_stats(20)
            console.print(stream.getvalue())

        code = exit_code(ctx.findings or [], result.coverage.unparsed_percentage)
        if code:
            sys.exit(code)

    except (ValueError, ExportError) as exc:
        console.print(f"[critical]ERROR: {exc}[/critical]")
        sys.exit(1)


@app.command()
def version() -> None:
    """Display version."""
    console.print(f"gc-analyze {__version__}")


if __name__ == "__main__":
    app()
