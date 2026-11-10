"""Shared helpers for the test suite."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from gc_analyze.events import normalize_event
from gc_analyze.models import GCEvent
from gc_analyze.parsers import detect_gc_type_and_create_parser

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> list[str]:
    """Lines of a fixture file."""
    with (FIXTURES / name).open() as handle:
        return handle.readlines()


def parse_lines(lines: list[str]) -> list[GCEvent]:
    """Detect, parse and normalize log lines."""
    parser = detect_gc_type_and_create_parser(lines)
    raw = parser.parse(lines)
    return [e for e in (normalize_event(r) for r in raw) if e is not None]


def kinds(events: list[GCEvent]) -> dict[str, int]:
    """Count events by kind."""
    counts: dict[str, int] = {}
    for event in events:
        counts[event.gc_kind] = counts.get(event.gc_kind, 0) + 1
    return counts


def approx(expected: float | list[float], *, abs: float | None = None) -> Any:
    """Typed wrapper around pytest.approx (its stub is partially unknown under strict mode)."""
    return pytest.approx(expected, abs=abs)  # pyright: ignore[reportUnknownMemberType]
