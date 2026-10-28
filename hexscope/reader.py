"""Input helpers: local files, bounded reads and stdin.

Everything in HexScope works on ``bytes``.  Large files are never slurped
wholesale unless the caller asks for it -- most analyses only need the first
few hundred kilobytes, and ``--limit`` exists precisely for that.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Optional

__all__ = ["Source", "read_bytes", "read_stdin", "DEFAULT_LIMIT"]

#: Default cap (bytes) applied when a command would otherwise read a huge file.
DEFAULT_LIMIT = 8 * 1024 * 1024  # 8 MiB


@dataclass
class Source:
    """Where the bytes came from -- kept around for report headers."""

    path: str
    is_stdin: bool = False
    size: Optional[int] = None
    truncated: bool = False

    @property
    def label(self) -> str:
        return "<stdin>" if self.is_stdin else self.path


def read_stdin() -> bytes:
    """Read *all* of stdin as binary."""
    try:
        data = sys.stdin.buffer.read()
    except AttributeError:  # pragma: no cover - defensive
        data = sys.stdin.read().encode("utf-8", "replace")
    return data


def read_bytes(
    path: str,
    offset: int = 0,
    limit: Optional[int] = None,
) -> tuple[bytes, Source]:
    """Read bytes from *path* (``-`` means stdin).

    Args:
        path: filesystem path, or ``-`` for stdin.
        offset: skip this many bytes before reading.
        limit: maximum number of bytes to return; ``None`` means "whole file"
            (still capped by :data:`DEFAULT_LIMIT` for regular files unless the
            caller passes a bigger value explicitly).

    Returns:
        ``(data, source)``.
    """
    if path == "-":
        data = read_stdin()
        if offset:
            data = data[offset:]
        if limit is not None:
            data = data[:limit]
        return data, Source(path="-", is_stdin=True, size=len(data))

    size = None
    try:
        size = _file_size(path)
    except OSError:
        size = None

    wanted = limit if limit is not None else DEFAULT_LIMIT
    truncated = False
    with open(path, "rb") as handle:
        if offset:
            handle.seek(offset)
        data = handle.read(wanted + 1)
    if size is not None and limit is None and size > DEFAULT_LIMIT:
        truncated = True
    if len(data) > wanted:
        data = data[:wanted]
        truncated = True
    return data, Source(path=path, size=size, truncated=truncated)


def _file_size(path: str) -> int:
    import os

    return os.path.getsize(path)
