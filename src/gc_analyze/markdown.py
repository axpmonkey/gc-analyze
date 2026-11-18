"""Markdown rendering of the report sections (full report and --brief)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from .report import Section, finding_lines, sanitize_text

# --brief: what goes into a case file (P2.4), in this order
BRIEF_SECTION_IDS: tuple[str, ...] = (
    "header",
    "unparsed",
    "diagnosis",
    "summary",
    "findings",
    "timeline",
    "comparison",
    "notes",
    "coverage",
    "segments",
    "full_gc_causes",
    "top_pauses",
    "floor",
    "floors",
    "config",
)
BRIEF_MAX_BYTES = 5000
BRIEF_TOP_PAUSES = 10
# Every critical and warning finding is listed (up to this many); info findings fill what is left
BRIEF_FINDINGS = 12
BRIEF_FLOORS = 12
BRIEF_TIMELINE_ROWS = 5


@dataclass(frozen=True)
class BriefDetail:
    """How much detail the brief keeps; findings and the summary are never cut."""

    floors: int  # 0 leaves the floors table out (the floor trend headline stays)
    top_pauses: int
    finding_times: bool
    timeline_rows: int = BRIEF_TIMELINE_ROWS
    info_findings: bool = True  # False lists only critical and warning findings
    data_notes: bool = True


# Tried in order until the brief fits: detail tables shrink first, then the findings lose
# their times, then informational findings and data notes go; critical and warning findings,
# the diagnosis and the summary always stay.
BRIEF_SHRINK_STEPS: tuple[BriefDetail, ...] = (
    BriefDetail(BRIEF_FLOORS, BRIEF_TOP_PAUSES, True),
    BriefDetail(6, BRIEF_TOP_PAUSES, True),
    BriefDetail(4, 5, True),
    BriefDetail(4, 3, True),
    BriefDetail(4, 3, False),
    BriefDetail(4, 3, False, data_notes=False),
    BriefDetail(0, 3, False),
    BriefDetail(0, 3, False, timeline_rows=3),
    BriefDetail(0, 3, False, timeline_rows=3, info_findings=False),
    BriefDetail(0, 3, False, timeline_rows=3, info_findings=False, data_notes=False),
)
# Flags that matter when reading a GC problem; the rest of the config is left out of --brief
BRIEF_CONFIG_LABELS: tuple[str, ...] = (
    "Initial Heap Size",
    "Maximum Heap Size",
    "New Generation Size",
    "Max New Generation Size",
    "Metaspace Size",
    "Max Metaspace Size",
    "Max GC Pause Target",
    "G1 Heap Region Size",
    "Initiating Heap Occupancy %",
    "CMS Initiating Occupancy Fraction",
    "Max RAM %",
)


def _cell(text: str) -> str:
    return sanitize_text(text).replace("|", "\\|").replace("\n", " ")


def _render_section(section: Section) -> str:
    title = sanitize_text(section.title)
    if section.id == "header":
        return f"**GC Type:** {sanitize_text(section.text)}\n\n"
    if section.id == "unparsed":
        return f"> **{sanitize_text(section.text)}**\n\n"
    if section.kind == "kv":
        lines = [f"## {title}\n\n"]
        lines += [
            f"- **{_cell(k)}:** {_cell(v)}\n" if v else f"- **{_cell(k)}**\n"
            for k, v in section.rows
        ]
        return "".join(lines) + "\n"
    if section.kind == "table":
        if not section.table_rows:
            return f"## {title}\n\n_None._\n\n"
        lines = [
            f"## {title}\n\n",
            "| " + " | ".join(_cell(h) for h in section.headers) + " |\n",
            "|" + "|".join("---" for _ in section.headers) + "|\n",
        ]
        lines += ["| " + " | ".join(_cell(c) for c in row) + " |\n" for row in section.table_rows]
        return "".join(lines) + "\n"
    if section.kind == "bullets":
        return f"## {title}\n\n" + "".join(f"- {sanitize_text(i)}\n" for i in section.items) + "\n"
    if section.kind == "findings":
        if not section.findings:
            return f"## {title}\n\n{section.text}\n\n"
        parts = [f"## {title}\n\n"]
        for number, finding in enumerate(section.findings, 1):
            parts.append(f"### {number}. [{finding.severity.upper()}] {_cell(finding.title)}\n\n")
            parts += [f"- **{label}:** {_cell(value)}\n" for label, value in finding_lines(finding)]
            parts.append("\n")
        return "".join(parts)
    body = sanitize_text(section.text).replace("\n", "  \n")
    return f"## {title}\n\n{body}\n\n"


def render_markdown(sections: list[Section], generated: datetime | None = None) -> str:
    """Full Markdown report."""
    stamp = (generated or datetime.now(UTC)).isoformat(timespec="seconds")
    parts = ["# GC Analysis Report\n\n", f"**Generated:** {stamp}\n\n"]
    parts += [_render_section(section) for section in sections]
    return "".join(parts)


def _paused_share(row: list[str]) -> float:
    """Share of time paused from a timeline row ("87.4% (262.2 s)"; "—" when none)."""
    text = row[2].split("%", 1)[0]
    return float(text) if text.replace(".", "", 1).isdigit() else 0.0


def _brief_section(section: Section, detail: BriefDetail) -> Section:
    floors_limit = detail.floors
    if section.id == "findings" and section.findings:
        # Keep each finding with one piece of evidence. The full report has the rest.
        serious = [f for f in section.findings if f.severity != "info"]
        info = [f for f in section.findings if f.severity == "info"] if detail.info_findings else []
        shown = serious + info[: max(0, BRIEF_FINDINGS - len(serious))]
        items = [
            f"[{f.severity.upper()}] {f.title}"
            + (f" ({f.when})" if f.when and (detail.finding_times or f.severity != "info") else "")
            + (f" [{f.confidence} confidence]" if f.confidence else "")
            + (f". {f.evidence[0]}" if f.evidence and f.evidence[0] != f.title else "")
            for f in shown
        ]
        hidden = len(section.findings) - len(shown)
        if hidden:
            items.append(f"... and {hidden} more in the full report")
        return Section(id="brief_findings", title="Findings", kind="bullets", items=items)
    if section.id == "timeline" and len(section.table_rows) > detail.timeline_rows:
        # the slices where the application was stopped most, kept in time order
        ranked = sorted(section.table_rows, key=_paused_share, reverse=True)[: detail.timeline_rows]
        rows = [row for row in section.table_rows if any(row is kept for kept in ranked)]
        return Section(
            id=section.id,
            title=(
                f"{section.title}: the {len(rows)} with the highest pause share "
                f"(of {len(section.table_rows)})"
            ),
            kind=section.kind,
            headers=section.headers,
            table_rows=rows,
        )
    if section.id == "top_pauses":
        rows = section.table_rows[: detail.top_pauses]
        return Section(
            id=section.id,
            title=f"Top {len(rows)} Longest Pauses",
            kind=section.kind,
            headers=section.headers,
            table_rows=rows,
        )
    if section.id == "floors" and len(section.table_rows) > floors_limit:
        rows = section.table_rows
        step = (len(rows) - 1) / (floors_limit - 1)
        picked = [rows[round(i * step)] for i in range(floors_limit)]
        return Section(
            id=section.id,
            title=f"{section.title} ({floors_limit} of {len(rows)}, evenly spaced)",
            kind=section.kind,
            headers=section.headers,
            table_rows=picked,
        )
    if section.id == "config":
        rows = [(k, v) for k, v in section.rows if k.startswith(BRIEF_CONFIG_LABELS)]
        return Section(id=section.id, title="Key JVM Flags", kind="kv", rows=rows)
    if section.id == "coverage":
        keep = ("GC event lines found", "GC event lines parsed", "GC event lines NOT parsed")
        rows = [(k, v) for k, v in section.rows if k in keep]
        rows += [(k, v) for k, v in section.rows if k == "Unparsed sample"][:2]
        return Section(id=section.id, title="Data Quality", kind="kv", rows=rows)
    return section


def render_brief_markdown(sections: list[Section], generated: datetime | None = None) -> str:
    """Target 5 KB while preserving the summary and warning evidence."""
    by_id = {s.id: s for s in sections}
    text = ""
    chosen: list[Section] = []
    for detail in BRIEF_SHRINK_STEPS:
        chosen = [
            _brief_section(by_id[i], detail)
            for i in BRIEF_SECTION_IDS
            if i in by_id
            and not (i == "floors" and detail.floors == 0)
            and not (i == "notes" and not detail.data_notes)
        ]
        text = render_markdown(chosen, generated).replace(
            "# GC Analysis Report", "# GC Analysis (brief)", 1
        )
        if len(text.encode()) <= BRIEF_MAX_BYTES:
            return text
    for kept in (
        {"header", "summary", "findings", "diagnosis", "coverage", "segments"},
        {"header", "summary", "findings"},
    ):
        text = render_markdown(
            [section for section in chosen if section.id in kept or section.id == "brief_findings"],
            generated,
        ).replace("# GC Analysis Report", "# GC Analysis (brief)", 1)
        if len(text.encode()) <= BRIEF_MAX_BYTES:
            return text
    return text
