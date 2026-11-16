# AGENTS.md

Guardrails for coding/auditing agents (Claude Code, OpenAI Codex, and similar). Self-contained and normative.
This is the single instruction file for the repo; `CLAUDE.md` only imports it.

**Project**: `gc-analyze` is a command-line utility that parses JVM garbage-collection (GC) logs and produces an operations-oriented summary: GC rate, pause distributions (P50/P95/P99), heap/old-gen pressure signals, and a memory-leak risk score with actionable recommendations.

## What it does

Given one or more GC log files, the tool:

- Detects the log format (Java 8 or JDK 9+ unified) and collector (G1, Parallel, CMS, Serial).
- Parses every stop-the-world pause (including multi-line records) with its cause into a common
  event model, and reports parsing coverage (lines found / parsed / not understood).
- Splits JVM restarts into segments, orders rotated files, and supports `--start/--end` windows.
- Computes pause statistics, heap vs max heap, Full GC causes, and the old-gen floor trend (leak signal).
- Emits a rich terminal report, optionally Markdown (`--output`, `--brief`) and events.jsonl.

---

## Core Rules

- **Plan first**: Draft a short plan (bullets) and emit it before any code changes.
- **Docs first**: Use Context7 MCP (or equivalent) to resolve library IDs and retrieve docs before generating code that uses external libraries.
- **Minimal edits**: Prefer minimal, reversible changes. Do not change public APIs or file layout unless explicitly requested.
- **Determinism**: All code and tests must be deterministic (no network, no nondeterministic time unless frozen).
- **Escalate**: Stop and escalate (open an issue or produce a note) if a task conflicts with these rules, requires API/layout changes without permission, or if required tools/docs are unavailable.
- **Current time**: Execute `date` command when asked about date/time or before web searches; SessionStart timestamps are static, not live.

---

## Design Principles

- **YAGNI**: Don't build it until you need it.
- **DRY**: Extract patterns after second duplication, not before.
- **Fail Fast**: Explicit errors beat silent failures.
- **Simple First**: Write the obvious solution, optimize only if needed.
- **Delete Aggressively**: Less code = fewer bugs.
- **Semantic Naming**: Always name variables, parameters, and API endpoints with verbose, self-documenting names that optimize for comprehension by both humans and LLMs, not brevity (e.g., `wait_until_obs_is_saved=true` vs `wait=true`).

---

## Toolchain

- **Python**: 3.15 only (`>=3.15,<3.16`, pinned in `.python-version`); do not support or test older versions
- **Formatter/Linter**: `ruff format` and `ruff check --fix`
- **Type checker**: `basedpyright` (strict)
- **Tests**: `pytest` with branch coverage >= 90%; optional `hypothesis`
- **Packaging**: `pyproject.toml` as single source of truth; `uv` exclusively (no pip/poetry/conda)
- **Dependencies**: Use the latest stable releases compatible with Python 3.15 for runtime, development, and build dependencies; update minimum versions in `pyproject.toml` when upgrading. Do not retain older versions for backward compatibility.
- **Bash tools**: `rg`, `fd`, `bat`, `jq` only (no grep/find)

---

## Verification

Run in sequence; **all must pass** before committing:

```bash
uv sync --frozen --extra dev
uv run --frozen --extra dev ruff format --check
uv run --frozen --extra dev ruff check
uv run --frozen --extra dev basedpyright
uv run --frozen --extra dev pytest -q --cov=src/gc_analyze --cov-branch --cov-fail-under=90  # only where tests/ exists
uv run --frozen --extra dev pip-audit  # or osv-scanner; fail on critical vulnerabilities
```

Environment: `TZ=UTC`, `PYTHONUTF8=1`, `LC_ALL=C.UTF-8`, `PYTHONWARNINGS=error`

Verify on Python 3.15 only; no multi-version Python matrix. Cache `uv` environments. Commit `uv.lock`.
Use `uv sync --upgrade --extra dev` to refresh dependencies to the latest compatible stable releases.
If an audit tool cannot run on Python 3.15, use `osv-scanner` or report the blocker; do not fall back to an older Python.

---

## Project Structure

```
src/gc_analyze/        # All package code
tests/                 # All tests (outside src/); maintainer-local, gitignored
pyproject.toml         # Single config file (all tool settings live here)
uv.lock                # Committed lockfile
```

- Prefer relative imports within a package; do not mutate `sys.path`.
- Define `__all__` for public exports.
- No `setup.py`.

---

## Code Standards

### Typing
- Complete type hints on all code; `from __future__ import annotations`.
- No implicit `Any`. No `# type: ignore` without justification.
- Prefer `Protocol` for behavioral contracts; use `Self`, `ParamSpec`, `TypeVarTuple` as appropriate.
- Use PEP 695 syntax for type parameters and type aliases; no compatibility fallbacks for older Python versions.

### I/O & HTTP
- Use `pathlib.Path` for filesystem work.
- Use `httpx` (not `requests`) with pooled clients, HTTP/2, explicit timeouts (never `None`), and retries only for idempotent methods with exponential backoff.
- Atomic writes: temp file + `Path.replace()`; `fsync` for critical paths.
- Access package data via `importlib.resources`.

### Data
- Prefer `pydantic` or `msgspec` for validation/serialization, using the latest stable release compatible with Python 3.15.
- Parameterized SQL only; never format/concatenate SQL with variables.
- Config via `pydantic-settings` (env + optional .env); env overrides file.

### CLI & Concurrency
- Prefer `typer` for CLI; if using Click, enforce typed callbacks and `main()` entrypoint.
- `asyncio`/`anyio` for I/O-bound; `concurrent.futures` for CPU-bound. No busy-waits.
- `tenacity` for retries with exponential backoff and jitter.

### Logging
- Use stdlib `logging` at module level: `logger = logging.getLogger(__name__)`.
- No `print()` in library code (CLI output only).
- Use `contextvars` for correlation IDs.

---

## Security

- Never commit secrets; use `pydantic-settings` for config.
- `yaml.safe_load` only; no untrusted pickle.
- Validate archive contents (tar/zip) for path traversal; block absolute and `..` paths.
- `subprocess.run([...], check=True, shell=False)` with explicit arg lists if shell needed.
- Explicit max sizes for file uploads/downloads.

---

## Testing

`tests/` is kept by the maintainer and is not committed (it is in `.gitignore`). When it is
present, the rules below apply; never `git add -f` it.

- Hermetic and network-free by default.
- Mock HTTP with `respx` or `httpx` mocking.
- Freeze time (`time-machine`/`freezegun`), seed randomness, enforce per-test timeouts.
- Branch coverage >= 90%.
- Test deprecation warnings with `warnings.warn(..., DeprecationWarning, stacklevel=2)`.

---

## Versioning

- Semantic versioning; expose `__version__` and CLI `--version` flag.
- Deprecation policy documented; deprecations tested.
