"""One report object per run; every output format is rendered from it.

``build_report`` turns an ``AnalysisResult`` into an ``AnalysisReport``: the findings, the
report sections and the machine-readable ``ReportDocument``. The terminal (Rich), Markdown,
brief Markdown and JSON outputs and the exit code all come from that one object, so they
cannot disagree.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from . import __version__
from .coverage import UNPARSED_WARNING_THRESHOLD_PCT
from .findings import Status, build_diagnosis, build_findings, overall_status
from .markdown import render_brief_markdown, render_markdown
from .models import CandidateCoverage, FileCoverage, Finding, GCSummary, SegmentInfo
from .pipeline import AnalysisResult
from .report import ReportContext, Section, build_sections

REPORT_SCHEMA_VERSION = 1


class ReportDocument(BaseModel):
    """The report as data (``--json``): conclusions first, then the figures behind them.

    Every percentage in ``summary`` sits next to the field that names its denominator
    (``heap.max_heap_source``, ``old_pct_basis``, ``floor_trend.capacity_source``, ...).
    """

    schema_version: int = REPORT_SCHEMA_VERSION
    tool: Literal["gc-analyze"] = "gc-analyze"
    version: str = __version__
    inputs: list[str]
    gc_type: str
    segment_label: str
    window_label: str | None
    status: Status
    exit_code: int
    diagnosis: str
    findings: list[Finding]
    summary: GCSummary
    comparison_label: str
    comparison: GCSummary | None
    segments: list[SegmentInfo]
    coverage: CandidateCoverage
    file_coverages: list[FileCoverage]


# Exit codes follow the monitoring-plugin convention (OK, WARNING, CRITICAL, UNKNOWN), so a
# monitoring system can run the command as a check
EXIT_OK = 0
EXIT_WARNING = 1  # warning findings, or too many GC lines not understood
EXIT_CRITICAL = 2  # critical findings
EXIT_CANNOT_ANALYZE = 3  # usage error, unreadable or unsupported log, failed output


def exit_code(findings: list[Finding], unparsed_pct: float) -> int:
    """EXIT_OK, EXIT_WARNING or EXIT_CRITICAL for a completed analysis.

    The same findings the report lists decide the code: informational findings do not count.
    """
    status = overall_status(findings)
    if status == "critical":
        return EXIT_CRITICAL
    if status == "warning" or unparsed_pct > UNPARSED_WARNING_THRESHOLD_PCT:
        return EXIT_WARNING
    return EXIT_OK


@dataclass
class AnalysisReport:
    """Everything one run concludes, ready to render in any format."""

    result: AnalysisResult
    findings: list[Finding]
    sections: list[Section]

    @property
    def exit_code(self) -> int:
        """Process exit code for these findings and this parse coverage."""
        return exit_code(self.findings, self.result.coverage.unparsed_percentage)

    def document(self) -> ReportDocument:
        """The report as data."""
        result = self.result
        return ReportDocument(
            inputs=[str(loaded.path) for loaded in result.files],
            gc_type=result.gc_type,
            segment_label=result.segment_label,
            window_label=result.window_label,
            status=overall_status(self.findings),
            exit_code=self.exit_code,
            diagnosis=build_diagnosis(result.summary, self.findings, result.coverage),
            findings=self.findings,
            summary=result.summary,
            comparison_label=result.comparison_label,
            comparison=result.comparison,
            segments=result.segments,
            coverage=result.coverage,
            file_coverages=result.file_coverages,
        )

    def json(self) -> str:
        """``document()`` as indented JSON (deterministic: no generation time)."""
        return self.document().model_dump_json(indent=2) + "\n"

    def markdown(self, *, brief: bool = False) -> str:
        """The full or brief Markdown report."""
        render = render_brief_markdown if brief else render_markdown
        return render(self.sections)


def build_report(result: AnalysisResult) -> AnalysisReport:
    """Findings and report sections for ``result``."""
    summary = result.summary
    findings = build_findings(summary, result.gc_type, result.events, result.coverage)
    context = ReportContext(
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
        inputs=[str(loaded.path) for loaded in result.files],
        findings=findings,
    )
    return AnalysisReport(result=result, findings=findings, sections=build_sections(context))
