# gc-analyze.py

A modern, type-safe Java GC (Garbage Collection) log analyzer for production troubleshooting and performance optimization.

## Overview

`gc-analyze.py` is a command-line tool that parses Java GC log files and generates comprehensive diagnostic reports with:

- **Memory leak detection** with severity scoring (0-100)
- **Pause time analysis** (P50, P95, P99 percentiles)
- **GC frequency and overhead metrics**
- **Heap and old generation utilization tracking**
- **Metaspace analysis**
- **Rich terminal output** with color-coded warnings and tables
- **Optional Markdown export** for sharing with teams

## Supported GC Types

- **Parallel GC** (PSYoungGen/ParOldGen)
- **G1 GC** (unified logging Java 9+ and legacy Java 8 format)
  - Mixed GC tracking
  - Humongous allocation detection
  - Evacuation failure monitoring
- **CMS GC** (Concurrent Mark Sweep with ParNew)
  - Concurrent cycle metrics
  - Concurrent mode failure detection

## Features

### Diagnostics

- **Memory Leak Detection**: Analyzes old generation growth patterns with severity scoring
- **Pause Time Analysis**: Statistical analysis of GC pause times (mean, median, P95, P99, max)
- **GC Overhead**: Calculates percentage of time spent in GC
- **Frequency Metrics**: Young GC and Full GC events per hour
- **Heap Utilization**: Tracks heap usage patterns and headroom
- **GC-Specific Metrics**:
  - G1: Mixed GC ratio, humongous allocations, evacuation failures
  - CMS: Concurrent cycles, concurrent mode failures

### Output

- **Rich Terminal UI**: Color-coded severity levels (green/yellow/red)
- **Formatted Tables**: Clear presentation of statistics and diagnostics
- **Markdown Export**: Generate shareable reports for team collaboration
- **Exit Codes**: Machine-readable status (0=success, 1=warnings, 2=critical)

## Installation and Usage

### Method 1: Using uv (Recommended)

`uv` is a fast Python package installer and environment manager. This is the recommended approach.

#### Initial Setup

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Navigate to the project directory
cd /path/to/gc-analyze

# Install Python 3.13 (if not already available)
uv python install 3.13

# Create virtual environment with Python 3.13
uv venv --python 3.13

# Sync dependencies (installs packages into the virtual environment)
uv sync
```

#### Run the Tool

```bash
# Analyze a GC log file
uv run python gc-analyze.py analyze gc.log

# Analyze with Markdown export
uv run python gc-analyze.py analyze gc.log --export report.md

# Analyze with custom thresholds
uv run python gc-analyze.py analyze gc.log --heap-warning 70 --heap-critical 90

# Verbose mode for debugging
uv run python gc-analyze.py analyze gc.log --verbose

# Display version and features
uv run python gc-analyze.py version
```

#### Update Dependencies

```bash
# Update all dependencies
uv sync --upgrade

# Add a new dependency
uv add <package-name>
```

### Method 2: Using pip and venv

Traditional Python workflow using pip and virtual environments.

#### Initial Setup

```bash
# Navigate to the project directory
cd /path/to/gc-analyze

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate

# Install dependencies
pip install pydantic typer rich
```

#### Run the Tool

After activating the virtual environment:

```bash
# Analyze a GC log file
python gc-analyze.py analyze gc.log

# Analyze with Markdown export
python gc-analyze.py analyze gc.log --export report.md

# Analyze with custom thresholds
python gc-analyze.py analyze gc.log --heap-warning 70 --heap-critical 90

# Verbose mode for debugging
python gc-analyze.py analyze gc.log --verbose

# Display version and features
python gc-analyze.py version
```

#### Deactivate Virtual Environment

```bash
deactivate
```

## Command Reference

### `analyze`

Analyze JVM GC log files and generate comprehensive diagnostic reports.

**Usage:**
```bash
gc-analyze.py analyze [OPTIONS] LOG_FILE
```

**Arguments:**
- `LOG_FILE` - Path to GC log file to analyze (required)

**Options:**
- `--export, -e PATH` - Export analysis report to Markdown file (e.g., report.md)
- `--heap-warning FLOAT` - Heap utilization percentage to trigger warnings (default: 80.0, range: 0-100)
- `--heap-critical FLOAT` - Heap utilization percentage to trigger critical alerts (default: 95.0, range: 0-100)
- `--verbose, -v` - Enable verbose output with detailed parsing information
- `--help` - Show help message

**Examples:**

```bash
# Basic analysis
uv run python gc-analyze.py analyze gc.log

# Export to Markdown
uv run python gc-analyze.py analyze gc.log --export report.md

# Custom thresholds
uv run python gc-analyze.py analyze gc.log --heap-warning 70 --heap-critical 90

# Debug parsing issues
uv run python gc-analyze.py analyze gc.log --verbose
```

### `version`

Display version and feature information.

**Usage:**
```bash
gc-analyze.py version
```

## Output Examples

### Terminal Output

The tool generates rich terminal output with:

- **Summary Panel**: Total events, time range, GC type detected
- **Statistics Table**: Pause times (mean, P50, P95, P99, max), heap usage, GC frequency
- **GC-Specific Metrics**: G1/CMS specific statistics when applicable
- **Diagnostics Section**: Color-coded warnings and recommendations
- **Leak Severity Score**: 0-100 scale with interpretation

### Markdown Export

When using `--export`, generates a comprehensive Markdown report including:

- Executive summary
- All statistics in table format
- Diagnostic findings
- Operational recommendations
- Suitable for sharing in tickets, documentation, or post-mortems

## Requirements

- **Python**: 3.11 or higher
- **Dependencies**:
  - `pydantic` >= 2.0 (data validation and parsing)
  - `typer` >= 0.9.0 (CLI framework)
  - `rich` >= 13.0 (terminal formatting)

## Typical Workflow

1. **Collect GC Logs**: Enable GC logging on your JVM with appropriate flags
   ```bash
   # Java 9+ unified logging
   -Xlog:gc*:file=gc.log:time,uptime,level,tags

   # Java 8
   -XX:+PrintGCDetails -XX:+PrintGCDateStamps -Xloggc:gc.log
   ```

2. **Analyze Logs**:
   ```bash
   uv run python gc-analyze.py analyze gc.log --export report.md
   ```

3. **Review Output**: Check terminal for immediate feedback and review Markdown report

4. **Take Action**: Follow diagnostic recommendations for tuning or troubleshooting

## Troubleshooting

### "No GC events parsed"

- Verify log format matches supported GC types
- Use `--verbose` to see parsing details
- Check that GC logging is enabled in JVM

### "Module not found" errors

- Ensure dependencies are installed: `uv sync` or `pip install pydantic typer rich`
- Verify virtual environment is activated (if using pip method)

### Incorrect metrics

- Ensure complete log file (not truncated)
- Verify timestamp format is consistent
- Check for mixed GC types in single log (may affect analysis)

## License

This tool is provided as-is for GC log analysis and diagnostics.

## Version

Current version: **3.0.0**

Built with Python 3.11+, Pydantic v2, Typer, and Rich.
