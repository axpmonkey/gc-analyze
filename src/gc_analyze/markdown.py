"""Markdown rendering of the report sections (full report and --brief)."""

from __future__ import annotations

from datetime import datetime

from .report import Section, sanitize_text

# --brief: what goes into a case file (P2.4), in this order
BRIEF_SECTION_IDS: tuple[str, ...] = (
    "header",
    "unparsed",
    "incident",
    "notes",
    "coverage",
    "segments",
    "comparison",
    "full_gc_causes",
    "top_pauses",
    "floor",
    "floors",
    "config",
    "warnings",
)
BRIEF_MAX_BYTES = 5000
BRIEF_TOP_PAUSES = 10
BRIEF_FLOORS = 12
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
    if section.id == "incident":
        return f"## {title}\n\n```\n{sanitize_text(section.text)}\n```\n\n"
    body = sanitize_text(section.text).replace("\n", "  \n")
    return f"## {title}\n\n{body}\n\n"


def render_markdown(sections: list[Section], generated: datetime | None = None) -> str:
    """Full Markdown report."""
    stamp = (generated or datetime.now()).isoformat(timespec="seconds")
    parts = ["# GC Analysis Report\n\n", f"**Generated:** {stamp}\n\n"]
    parts += [_render_section(section) for section in sections]
    return "".join(parts)


def _brief_section(section: Section, floors_limit: int) -> Section:
    if section.id == "top_pauses":
        rows = section.table_rows[:BRIEF_TOP_PAUSES]
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
    """Case-file sized summary (P2.4): kept under ~5 KB."""
    by_id = {s.id: s for s in sections}
    floors_limit = BRIEF_FLOORS
    text = ""
    for _ in range(4):
        chosen = [_brief_section(by_id[i], floors_limit) for i in BRIEF_SECTION_IDS if i in by_id]
        text = render_markdown(chosen, generated).replace(
            "# GC Analysis Report", "# GC Analysis (brief)", 1
        )
        if len(text.encode()) <= BRIEF_MAX_BYTES:
            return text
        floors_limit = max(4, floors_limit // 2)
    return text[:BRIEF_MAX_BYTES].rsplit("\n", 1)[0] + "\n\n_(truncated to 5 KB)_\n"
