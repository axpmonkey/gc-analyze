"""JVM heap and GC tuning flags from the 'CommandLine flags:' header."""

from __future__ import annotations

import re
from typing import Any

from .models import JVMHeapConfig


def parse_jvm_size_to_bytes(value: str, unit: str | None) -> int:
    """Convert JVM size notation to bytes.

    Args:
        value: Numeric value as string
        unit: Unit suffix (k/m/g or None for bytes)

    Returns:
        Size in bytes
    """
    num = int(value)
    if unit is None:
        return num

    unit_lower = unit.lower()
    if unit_lower == "k":
        return num * 1024
    elif unit_lower == "m":
        return num * 1024 * 1024
    elif unit_lower == "g":
        return num * 1024 * 1024 * 1024
    return num


def parse_jvm_heap_config(log_lines: list[str]) -> JVMHeapConfig | None:
    """Extract JVM heap and GC tuning arguments from CommandLine flags.

    Args:
        log_lines: Raw GC log lines

    Returns:
        JVMHeapConfig if CommandLine flags found, None otherwise
    """
    # Pattern to match CommandLine flags line
    commandline_pattern = re.compile(r"CommandLine flags:\s*(.+)")

    # Heap-related flag patterns (byte values)
    byte_patterns = {
        "initial_heap_size_bytes": re.compile(r"-XX:InitialHeapSize=(\d+)"),
        "max_heap_size_bytes": re.compile(r"-XX:MaxHeapSize=(\d+)"),
        "new_size_bytes": re.compile(r"-XX:NewSize=(\d+)"),
        "max_new_size_bytes": re.compile(r"-XX:MaxNewSize=(\d+)"),
        "old_size_bytes": re.compile(r"-XX:OldSize=(\d+)"),
        "max_ram_bytes": re.compile(r"-XX:MaxRAM=(\d+)"),
        "soft_max_heap_size_bytes": re.compile(r"-XX:SoftMaxHeapSize=(\d+)"),
        "metaspace_size_bytes": re.compile(r"-XX:MetaspaceSize=(\d+)"),
        "max_metaspace_size_bytes": re.compile(r"-XX:MaxMetaspaceSize=(\d+)"),
        "max_direct_memory_size_bytes": re.compile(r"-XX:MaxDirectMemorySize=(\d+)"),
        "g1_heap_region_size_bytes": re.compile(r"-XX:G1HeapRegionSize=(\d+)"),
    }

    # Integer/percentage patterns
    int_patterns = {
        "new_ratio": re.compile(r"-XX:NewRatio=(\d+)"),
        "survivor_ratio": re.compile(r"-XX:SurvivorRatio=(\d+)"),
        "initial_survivor_ratio": re.compile(r"-XX:InitialSurvivorRatio=(\d+)"),
        "target_survivor_ratio": re.compile(r"-XX:TargetSurvivorRatio=(\d+)"),
        "max_tenuring_threshold": re.compile(r"-XX:MaxTenuringThreshold=(\d+)"),
        "max_heap_free_ratio": re.compile(r"-XX:MaxHeapFreeRatio=(\d+)"),
        "min_heap_free_ratio": re.compile(r"-XX:MinHeapFreeRatio=(\d+)"),
        "parallel_gc_threads": re.compile(r"-XX:ParallelGCThreads=(\d+)"),
        "conc_gc_threads": re.compile(r"-XX:ConcGCThreads=(\d+)"),
        "max_gc_pause_millis": re.compile(r"-XX:MaxGCPauseMillis=(\d+)"),
        "gc_time_ratio": re.compile(r"-XX:GCTimeRatio=(\d+)"),
        "adaptive_size_policy_weight": re.compile(r"-XX:AdaptiveSizePolicyWeight=(\d+)"),
        "initial_ram_percentage": re.compile(r"-XX:InitialRAMPercentage=(\d+)"),
        "min_ram_percentage": re.compile(r"-XX:MinRAMPercentage=(\d+)"),
        "max_ram_percentage": re.compile(r"-XX:MaxRAMPercentage=(\d+)"),
        "max_ram_fraction": re.compile(r"-XX:MaxRAMFraction=(\d+)"),
        "thread_stack_size_kb": re.compile(r"-XX:ThreadStackSize=(\d+)"),
        "initiating_heap_occupancy_percent": re.compile(
            r"-XX:InitiatingHeapOccupancyPercent=(\d+)"
        ),
        "g1_reserve_percent": re.compile(r"-XX:G1ReservePercent=(\d+)"),
        "g1_new_size_percent": re.compile(r"-XX:G1NewSizePercent=(\d+)"),
        "g1_max_new_size_percent": re.compile(r"-XX:G1MaxNewSizePercent=(\d+)"),
        "g1_mixed_gc_count_target": re.compile(r"-XX:G1MixedGCCountTarget=(\d+)"),
        "g1_heap_waste_percent": re.compile(r"-XX:G1HeapWastePercent=(\d+)"),
        "g1_mixed_gc_live_threshold_percent": re.compile(
            r"-XX:G1MixedGCLiveThresholdPercent=(\d+)"
        ),
        "g1_rset_updating_pause_time_percent": re.compile(
            r"-XX:G1RSetUpdatingPauseTimePercent=(\d+)"
        ),
        "g1_old_cset_region_threshold_percent": re.compile(
            r"-XX:G1OldCSetRegionThresholdPercent=(\d+)"
        ),
        "cms_initiating_occupancy_fraction": re.compile(
            r"-XX:CMSInitiatingOccupancyFraction=(\d+)"
        ),
        "cms_full_gcs_before_compaction": re.compile(r"-XX:CMSFullGCsBeforeCompaction=(\d+)"),
        "cms_wait_duration": re.compile(r"-XX:CMSWaitDuration=(\d+)"),
    }

    bool_patterns = {
        "always_pre_touch": re.compile(r"-XX:\+AlwaysPreTouch"),
        "use_adaptive_size_policy": re.compile(r"-XX:\+UseAdaptiveSizePolicy"),
        "use_adaptive_size_policy_footprint_goal": re.compile(
            r"-XX:\+UseAdaptiveSizePolicyFootprintGoal"
        ),
        "use_cms_initiating_occupancy_only": re.compile(r"-XX:\+UseCMSInitiatingOccupancyOnly"),
    }

    # Also support -Xms, -Xmx, -Xmn formats
    xms_pattern = re.compile(r"-Xms(\d+)([kmgKMG])?")
    xmx_pattern = re.compile(r"-Xmx(\d+)([kmgKMG])?")
    xmn_pattern = re.compile(r"-Xmn(\d+)([kmgKMG])?")

    # Search for CommandLine flags
    for line in log_lines:
        if match := commandline_pattern.search(line):
            flags_str = match.group(1)
            config_dict: dict[str, Any] = {}

            # Parse byte-value flags
            for field, pattern in byte_patterns.items():
                if field_match := pattern.search(flags_str):
                    value = int(field_match.group(1))
                    config_dict[field] = value

            # Parse integer/percentage flags
            for field, pattern in int_patterns.items():
                if field_match := pattern.search(flags_str):
                    value = int(field_match.group(1))
                    config_dict[field] = value

            # Parse -Xms, -Xmx, -Xmn (convert to bytes, override if present)
            if xms := xms_pattern.search(flags_str):
                config_dict["initial_heap_size_bytes"] = parse_jvm_size_to_bytes(
                    xms.group(1), xms.group(2)
                )
            if xmx := xmx_pattern.search(flags_str):
                config_dict["max_heap_size_bytes"] = parse_jvm_size_to_bytes(
                    xmx.group(1), xmx.group(2)
                )
            if xmn := xmn_pattern.search(flags_str):
                config_dict["new_size_bytes"] = parse_jvm_size_to_bytes(xmn.group(1), xmn.group(2))

            # Parse boolean flags
            for field, pattern in bool_patterns.items():
                if pattern.search(flags_str):
                    config_dict[field] = True

            if config_dict:
                return JVMHeapConfig(**config_dict)

    # No CommandLine flags (unified logging, JDK 9+): pick up what the startup lines state.
    # The max heap is resolved separately (parse_max_heap_from_log) so its source is labelled.
    unified_region_size_pattern = re.compile(
        r"Heap region size:\s*(\d+)\s*(MB|KB|M|K)?", re.IGNORECASE
    )
    unified_workers_pattern = re.compile(r"Using\s+(\d+)\s+workers?\s+of\s+(\d+)")

    unified_config: dict[str, Any] = {}

    for line in log_lines:
        if match := unified_region_size_pattern.search(line):
            size_value = int(match.group(1))
            unit = (match.group(2) or "M").upper()
            multiplier = 1024 if unit in ("KB", "K") else 1024 * 1024
            unified_config["g1_heap_region_size_bytes"] = size_value * multiplier
        if "parallel_gc_threads" not in unified_config and (
            match := unified_workers_pattern.search(line)
        ):
            unified_config["parallel_gc_threads"] = int(match.group(2))

    if unified_config:
        return JVMHeapConfig(**unified_config)

    return None


# Unified logging startup lines that state the maximum heap:
#   JDK 11:  "[gc,heap,coops] Heap address: 0x0000000740000000, size: 3072 MB, ..."
#   JDK 17+: "[gc,init] Heap Max Capacity: 3G"
_UNIFIED_MAX_HEAP = (
    re.compile(r"Heap Max Capacity:\s+(?P<value>\d+(?:\.\d+)?)(?P<unit>[KMGT]?)B?\b"),
    re.compile(r"Heap address: 0x[0-9a-fA-F]+, size: (?P<value>\d+) (?P<unit>[KMGT]?)B\b"),
)
_UNIT_BYTES = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}


def parse_max_heap_from_log(log_lines: list[str]) -> int | None:
    """Max heap in bytes from unified-logging startup lines, if present."""
    for line in log_lines[:400]:
        if "Heap" not in line:
            continue
        for pattern in _UNIFIED_MAX_HEAP:
            if match := pattern.search(line):
                return int(float(match.group("value")) * _UNIT_BYTES[match.group("unit")])
    return None


_SIZE_ARG = re.compile(r"^(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>[kmgtKMGT]?)[bB]?$")


def parse_size_argument(text: str) -> int:
    """Parse a size like "4g", "3072m", "4294967296" into bytes."""
    match = _SIZE_ARG.match(text.strip())
    if match is None:
        raise ValueError(f"not a size: {text!r} (use e.g. 4g, 3072m)")
    return int(float(match.group("value")) * _UNIT_BYTES[match.group("unit").upper()])
