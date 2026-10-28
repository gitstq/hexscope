"""Byte-value frequency histogram with a terminal bar renderer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence

from .colors import C

from .entropy import byte_counts

__all__ = ["Histogram", "build_histogram", "render_bars"]

_CATEGORIES = [
    (0x00, 0x00, "NUL"),
    (0x01, 0x08, "control"),
    (0x09, 0x0D, "whitespace"),
    (0x0E, 0x1F, "control"),
    (0x20, 0x20, "space"),
    (0x21, 0x2F, "punctuation"),
    (0x30, 0x39, "digit"),
    (0x3A, 0x40, "punctuation"),
    (0x41, 0x5A, "upper A-Z"),
    (0x5B, 0x60, "punctuation"),
    (0x61, 0x7A, "lower a-z"),
    (0x7B, 0x7E, "punctuation"),
    (0x7F, 0x7F, "DEL"),
    (0x80, 0xBF, "continuation/high"),
    (0xC0, 0xFF, "high byte"),
]


def _category(value: int) -> str:
    for low, high, name in _CATEGORIES:
        if low <= value <= high:
            return name
    return "other"


@dataclass
class Histogram:
    """256-slot byte histogram plus derived summaries."""

    counts: List[int] = field(default_factory=list)
    size: int = 0

    def __post_init__(self) -> None:
        if not self.counts:
            self.counts = [0] * 256
        if self.size == 0:
            self.size = sum(self.counts)

    # -- queries ---------------------------------------------------------
    def top(self, n: int = 16) -> List[tuple[int, int]]:
        ordered = sorted(
            ((value, count) for value, count in enumerate(self.counts) if count),
            key=lambda item: (-item[1], item[0]),
        )
        return ordered[:n]

    def coverage(self, n: int = 16) -> float:
        """Share of the file covered by the *n* most common byte values."""
        if not self.size:
            return 0.0
        return sum(count for _, count in self.top(n)) / self.size

    def by_category(self) -> List[tuple[str, int, float]]:
        buckets: dict[str, int] = {}
        for value, count in enumerate(self.counts):
            if count:
                buckets[_category(value)] = buckets.get(_category(value), 0) + count
        total = self.size or 1
        ordered = sorted(buckets.items(), key=lambda item: -item[1])
        return [(name, count, count / total) for name, count in ordered]

    # -- serialisation ---------------------------------------------------
    def to_dict(self, top: int = 16) -> dict:
        return {
            "size": self.size,
            "distinct": sum(1 for count in self.counts if count),
            "top_coverage": round(self.coverage(top), 6),
            "top": [
                {"byte": f"0x{v:02x}", "char": _char(v), "count": c, "pct": round(c / (self.size or 1) * 100, 3)}
                for v, c in self.top(top)
            ],
            "categories": [
                {"name": name, "count": count, "pct": round(pct * 100, 3)}
                for name, count, pct in self.by_category()
            ],
        }

    def render_text(self, top: int = 16, width: int = 40) -> str:
        lines: List[str] = []
        lines.append(C.title(f"Byte histogram — top {top} of {sum(1 for c in self.counts if c)} values"))
        peak = max((count for _, count in self.top(top)), default=1)
        for value, count in self.top(top):
            pct = count / (self.size or 1) * 100
            bar_len = int(round(count / peak * width)) if peak else 0
            bar = "█" * max(bar_len, 1)
            lines.append(
                f"  {C.key(f'0x{value:02x}')} {C.dim(_char(value))}  "
                f"{C.ascii_bar(bar.ljust(width))} {count:>9}  {pct:5.2f}%"
            )
        lines.append("")
        lines.append(C.title("Byte classes"))
        for name, count, pct in self.by_category():
            bar_len = int(round(pct * width))
            lines.append(
                f"  {C.key(name.ljust(18))} {C.ascii_bar(('█' * max(bar_len, 1)).ljust(width))} {pct * 100:5.2f}%"
            )
        return "\n".join(lines)


def _char(value: int) -> str:
    if 0x20 <= value < 0x7F:
        return chr(value)
    if value in (0x09,):
        return "\\t"
    if value in (0x0A,):
        return "\\n"
    if value in (0x0D,):
        return "\\r"
    if value == 0x00:
        return "\\0"
    return "."


def build_histogram(data: bytes) -> Histogram:
    """Build a :class:`Histogram` for *data*."""
    counts = byte_counts(data)
    return Histogram(counts=counts, size=len(data))


def render_bars(values: Sequence[int], width: int = 40, glyph: str = "█") -> List[str]:
    """Render an arbitrary series of counts as bars (shared helper)."""
    peak = max(values) if values else 0
    out: List[str] = []
    for value in values:
        length = int(round(value / peak * width)) if peak else 0
        out.append(glyph * max(length, 1))
    return out
