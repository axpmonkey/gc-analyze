"""End-to-end command-line behaviour: options, outputs, exit codes."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from gc_analyze.cli import app

from .support import FIXTURES

runner = CliRunner()


def run(*args: str) -> tuple[int, str]:
    result = runner.invoke(app, ["analyze", *args], env={"COLUMNS": "150"})
    return result.exit_code, result.output


def test_exit_codes() -> None:
    assert run(str(FIXTURES / "parallel_unified.log"))[0] == 0  # clean
    assert run(str(FIXTURES / "cms.log"))[0] == 1  # warnings
    assert run(str(FIXTURES / "cms_failures.log"))[0] == 2  # critical


def test_incomplete_parse_exits_one(tmp_path: Path) -> None:
    log = tmp_path / "partial.log"
    log.write_text(
        (FIXTURES / "parallel_unified.log").read_text()
        + "[1.0s][info][gc] GC(9) Pause Young (x) 1ms\n"
    )
    code, output = run(str(log))
    assert code == 1
    assert "Incomplete Parse" in output


def test_markdown_and_brief_outputs(tmp_path: Path) -> None:
    full = tmp_path / "full.md"
    brief = tmp_path / "brief.md"
    assert run(str(FIXTURES / "cms_failures.log"), "--output", str(full))[0] == 2
    assert run(str(FIXTURES / "cms_failures.log"), "--output", str(brief), "--brief")[0] == 2
    assert full.read_text().startswith("# GC Analysis Report")
    assert brief.read_text().startswith("# GC Analysis (brief)")
    assert len(brief.read_bytes()) <= 5000
    assert len(brief.read_bytes()) < len(full.read_bytes())


def test_brief_to_stdout() -> None:
    code, output = run(str(FIXTURES / "g1legacy_details.log"), "--brief")
    assert code == 0
    assert output.startswith("# GC Analysis (brief)")
    assert "Incident Summary" in output


def test_export_events_and_host(tmp_path: Path) -> None:
    path = tmp_path / "gc.events.jsonl"
    code, output = run(
        str(FIXTURES / "g1unified_time.log"), "--export-events", str(path), "--host", "host-07"
    )
    assert "10 events exported" in output
    records = [json.loads(line) for line in path.read_text().splitlines()]
    assert {r["host"] for r in records} == {"host-07"}
    assert records[0]["attrs"]["max_heap_kb"] == 1048576
    assert code == 1


def test_export_without_wall_clock_is_an_error(tmp_path: Path) -> None:
    code, output = run(
        str(FIXTURES / "serial_legacy.log"), "--export-events", str(tmp_path / "x.jsonl")
    )
    assert code == 1
    assert "needs wall-clock time" in output


def test_max_heap_option() -> None:
    code, output = run(str(FIXTURES / "cms.log"), "--max-heap", "16g")
    assert "16.00 GB (from --max-heap)" in output
    code, output = run(str(FIXTURES / "cms.log"), "--max-heap", "lots")
    assert code == 2
    assert "not a size" in output


def test_window_options(tmp_path: Path) -> None:
    code, output = run(
        str(FIXTURES / "parallel_floor_slope.log"),
        "--start",
        "2023-04-01T02:00:00",
        "--end",
        "2023-04-01T05:00:00",
    )
    assert "window 2023-04-01T02:00:00-04:00 to 2023-04-01T05:00:00-04:00" in output
    assert re.search(r"Total pauses\s+19\b", output)  # 4 Full + 15 young
    code, output = run(str(FIXTURES / "parallel_floor_slope.log"), "--start", "tomorrow")
    assert code == 1
    assert "not an ISO 8601 time" in output


def test_segment_option_and_listing() -> None:
    code, output = run(str(FIXTURES / "restart_in_middle.log"))
    assert "JVM Runs Found (analyzing segment 2 of 2)" in output
    code, output = run(str(FIXTURES / "restart_in_middle.log"), "--segment", "1")
    assert "segment 1 of 2" in output
    code, output = run(str(FIXTURES / "restart_in_middle.log"), "--segment", "7")
    assert code == 1
    assert "segments 1-2" in output


def test_multiple_files(tmp_path: Path) -> None:
    _, output = run(str(FIXTURES / "cms.log"), str(FIXTURES / "cms_failures.log"))
    assert "Input Files" in output


def test_thresholds_options() -> None:
    _, output = run(str(FIXTURES / "parallel_floor_slope.log"), "--min-rate-window", "1000")
    assert "window too short for a rate" in output
    _, output = run(
        str(FIXTURES / "parallel_floor_slope.log"), "--heap-warning", "50", "--full-gc-streak", "2"
    )
    assert "WARNING: Heap after GC peaked" in output


def test_verbose_and_profile(tmp_path: Path) -> None:
    profile = tmp_path / "p.prof"
    _, output = run(str(FIXTURES / "cms.log"), "-v", "--profile", "--profile-output", str(profile))
    assert "CMS GC (legacy)" in output
    assert "cumulative" in output
    assert profile.exists()


def test_jvm_start_option_errors() -> None:
    code, output = run(str(FIXTURES / "serial_legacy.log"), "--jvm-start", "2026-01-01T00:00:00")
    assert code == 2
    assert "UTC offset" in output


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.output.strip() == "gc-analyze 4.0.0"
