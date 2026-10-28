"""Printable-string extraction (the ``strings`` command, ours).

Supports ASCII/UTF-8, UTF-16LE, UTF-16BE and a permissive latin-1 mode.
Every hit keeps its byte offset so it can be cross-referenced with a hex
dump or fed into a carve/report pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Pattern

from .colors import C

__all__ = ["StringHit", "StringResult", "extract_strings", "ENCODINGS"]

ENCODINGS = ("ascii", "utf-8", "utf-16-le", "utf-16-be", "latin-1")

def _ascii_repeat(min_len: int) -> Pattern[bytes]:
    return re.compile(rb"[\x20-\x7e]{%d,}" % min_len)


@dataclass
class StringHit:
    """One extracted string."""

    offset: int
    text: str
    encoding: str
    length: int

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "text": self.text,
            "encoding": self.encoding,
            "length": self.length,
        }


@dataclass
class StringResult:
    """Collection of hits with the parameters that produced them."""

    hits: List[StringHit] = field(default_factory=list)
    min_len: int = 4
    encoding: str = "ascii"
    pattern: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "min_len": self.min_len,
            "encoding": self.encoding,
            "pattern": self.pattern,
            "count": len(self.hits),
            "strings": [hit.to_dict() for hit in self.hits],
        }

    def render_text(self, show_offset: bool = True, limit: int = 200) -> str:
        lines: List[str] = []
        for hit in self.hits[:limit]:
            prefix = f"{C.offset(f'0x{hit.offset:08x}')}  " if show_offset else ""
            lines.append(f"{prefix}{C.ascii_bar(hit.text)}")
        if len(self.hits) > limit:
            lines.append(C.dim(f"… {len(self.hits) - limit} more strings"))
        if not self.hits:
            lines.append(C.warn("No printable strings found."))
        return "\n".join(lines)


def extract_strings(
    data: bytes,
    min_len: int = 4,
    encoding: str = "ascii",
    pattern: Optional[str] = None,
    limit: Optional[int] = None,
) -> StringResult:
    """Extract printable runs from *data*.

    Args:
        data: input bytes.
        min_len: minimum run length (bytes) to keep.
        encoding: one of :data:`ENCODINGS`.
        pattern: optional Python regex applied to the *decoded* text.
        limit: stop after this many hits.

    Returns:
        A :class:`StringResult`.
    """
    if min_len < 1:
        raise ValueError("min_len must be >= 1")
    if encoding not in ENCODINGS:
        raise ValueError(f"encoding must be one of {ENCODINGS}")

    regex = re.compile(pattern) if pattern else None
    hits: List[StringHit] = []

    if encoding in ("ascii", "utf-8"):
        regex_bytes = _ascii_repeat(min_len)
        for match in regex_bytes.finditer(data):
            raw = match.group(0)
            text = raw.decode("utf-8" if encoding == "utf-8" else "ascii", "replace")
            hits.append(
                StringHit(offset=match.start(), text=text, encoding=encoding, length=len(raw))
            )
    elif encoding == "utf-16-le":
        for match in re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _ceil(min_len, 2)).finditer(data):
            raw = match.group(0)
            if len(raw) < min_len:
                continue
            text = raw.decode("utf-16-le", "replace")
            hits.append(StringHit(offset=match.start(), text=text, encoding=encoding, length=len(raw)))
    elif encoding == "utf-16-be":
        for match in re.compile(rb"(?:\x00[\x20-\x7e]){%d,}" % _ceil(min_len, 2)).finditer(data):
            raw = match.group(0)
            if len(raw) < min_len:
                continue
            text = raw.decode("utf-16-be", "replace")
            hits.append(StringHit(offset=match.start(), text=text, encoding=encoding, length=len(raw)))
    else:  # latin-1
        for match in re.compile(rb"[\x20-\x7e\xa0-\xff]{%d,}" % min_len).finditer(data):
            raw = match.group(0)
            text = raw.decode("latin-1")
            hits.append(StringHit(offset=match.start(), text=text, encoding=encoding, length=len(raw)))

    if regex:
        hits = [hit for hit in hits if regex.search(hit.text)]

    hits.sort(key=lambda hit: hit.offset)
    if limit is not None:
        hits = hits[:limit]

    return StringResult(hits=hits, min_len=min_len, encoding=encoding, pattern=pattern)


def _ceil(value: int, unit: int) -> int:
    return max(1, -(-value // unit))


def summarise(hits: Iterable[StringHit], top: int = 10) -> List[tuple[str, int]]:
    """Most frequent strings (handy for quick triage)."""
    counts: dict[str, int] = {}
    for hit in hits:
        counts[hit.text] = counts.get(hit.text, 0) + 1
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return ordered[:top]
