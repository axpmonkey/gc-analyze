"""Writing output files so that a reader never sees one half-written."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def write_text_atomic(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` through a temporary file in the same directory.

    A reader never sees a half-written report: the file appears complete or not at all.
    An error names ``path``, not the temporary file.
    """
    directory = path.parent if str(path.parent) else Path()
    try:
        descriptor, temporary = tempfile.mkstemp(
            dir=directory, prefix=f".{path.name}.", suffix=".tmp"
        )
    except OSError as exc:
        raise OSError(f"cannot write {path}: {exc.strerror}") from exc
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
