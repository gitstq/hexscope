"""Shannon entropy analysis: whole-file, blocked and sliding-window.

Entropy is the quickest way to answer "is this compressed / encrypted /
plain text?" without knowing anything about the format.  This module is
written from scratch (``math.log2`` + a 256-slot counter) and is exact for
the byte-level definition:

    H = -Σ p(i) · log2 p(i)          (0.0 ≤ H ≤ 8.0)
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from .colors import C

__all__ = [
    "shannon_entropy",
    "byte_counts",
    "block_entropies",
    "sliding_entropy",
    "classify_entropy",
    "render_sparkline",
    "EntropyReport",
]

#: Sparkline glyphs, low → high.  ASCII fallback keeps Windows consoles happy.
SPARK_UNICODE = "▁▂▃▄▅▆▇█"
SPARK_ASCII = " .:-=+*#"


def byte_counts(data: bytes) -> List[int]:
    """Return a 256-slot histogram of byte values."""
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    return counts


def shannon_entropy(data: bytes, counts: Sequence[int] | None = None) -> float:
    """Byte-level Shannon entropy in bits (0.0 – 8.0)."""
    if not data:
        return 0.0
    if counts is None:
        counts = byte_counts(data)
    total = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    # Guard against floating point drift beyond the theoretical maximum.
    return min(8.0, max(0.0, entropy))


def block_entropies(data: bytes, block_size: int = 256) -> List[tuple[int, float]]:
    """Entropy of consecutive, non-overlapping blocks.

    Returns:
        ``[(offset, entropy), ...]`` -- the last block may be shorter.
    """
    if block_size < 1:
        raise ValueError("block_size must be >= 1")
    out: List[tuple[int, float]] = []
    for offset in range(0, len(data), block_size):
        chunk = data[offset : offset + block_size]
        out.append((offset, shannon_entropy(chunk)))
    return out


def sliding_entropy(data: bytes, window: int = 1024, step: int = 256) -> List[tuple[int, float]]:
    """Entropy of an overlapping sliding window.

    Args:
        data: input bytes.
        window: window size in bytes.
        step: advance between windows (``step == window`` == blocked mode).
    """
    if window < 1 or step < 1:
        raise ValueError("window and step must be >= 1")
    if not data:
        return []
    # Small inputs: shrink the window so the profile still shows ~8 samples
    # instead of a single, meaningless point.
    window = min(window, max(len(data) // 8, 1))
    step = min(step, window)
    if len(data) <= window:
        return [(0, shannon_entropy(data))]
    out: List[tuple[int, float]] = []
    position = 0
    while position + window <= len(data):
        out.append((position, shannon_entropy(data[position : position + window])))
        position += step
    # Always include a final window anchored at EOF for tail coverage.
    last = len(data) - window
    if out and out[-1][0] != last:
        out.append((last, shannon_entropy(data[last : last + window])))
    return out


def classify_entropy(value: float) -> str:
    """Human label for an entropy value (heuristic, documented as such)."""
    if value < 1.0:
        return "very-low"
    if value < 3.5:
        return "structured"
    if value < 5.0:
        return "text-like"
    if value < 6.8:
        return "mixed"
    if value < 7.6:
        return "compressed"
    return "encrypted/random"


def render_sparkline(
    values: Sequence[float],
    height: int = 1,
    width: int | None = None,
    minimum: float = 0.0,
    maximum: float = 8.0,
    ascii_only: bool = False,
) -> List[str]:
    """Render *values* as one or more sparkline rows.

    With ``height == 1`` a single unicode sparkline is produced; with larger
    heights a column chart is produced, top row = highest value.
    """
    glyphs = SPARK_ASCII if ascii_only else SPARK_UNICODE
    if not values:
        return []
    series = list(values)
    if width is not None and len(series) > width:
        series = _resample(series, width)
    span = max(maximum - minimum, 1e-9)
    levels = len(glyphs)
    rows: List[str] = []
    if height <= 1:
        row = "".join(glyphs[_bucket(value, minimum, span, levels)] for value in series)
        rows.append(row)
        return rows
    for level in range(height, 0, -1):
        threshold = (level - 0.5) / height
        row = "".join(
            "█" if (value - minimum) / span >= threshold else " "
            for value in series
        )
        rows.append(row)
    return rows


def _bucket(value: float, minimum: float, span: float, levels: int) -> int:
    normalised = (value - minimum) / span
    normalised = min(1.0, max(0.0, normalised))
    return int(round(normalised * (levels - 1)))


def _resample(values: Sequence[float], width: int) -> List[float]:
    """Down-sample by averaging buckets (keeps peaks visible)."""
    out: List[float] = []
    size = len(values) / width
    for index in range(width):
        start = int(index * size)
        end = max(start + 1, int((index + 1) * size))
        bucket = values[start:end]
        if bucket:
            out.append(sum(bucket) / len(bucket))
    return out


@dataclass
class EntropyReport:
    """Aggregated entropy view used by ``hexscope entropy`` and ``stats``."""

    size: int
    overall: float
    overall_label: str
    blocks: List[tuple[int, float]] = field(default_factory=list)
    windows: List[tuple[int, float]] = field(default_factory=list)
    distinct_bytes: int = 0
    most_common: List[tuple[int, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "entropy": round(self.overall, 6),
            "label": self.overall_label,
            "distinct_bytes": self.distinct_bytes,
            "most_common": [
                {"byte": f"0x{value:02x}", "count": count}
                for value, count in self.most_common
            ],
            "blocks": [
                {"offset": offset, "entropy": round(value, 6)}
                for offset, value in self.blocks
            ],
            "windows": [
                {"offset": offset, "entropy": round(value, 6)}
                for offset, value in self.windows
            ],
        }

    def render_text(
        self,
        show_blocks: bool = True,
        spark_width: int = 64,
        ascii_only: bool = False,
    ) -> str:
        """Terminal-friendly rendering."""
        lines: List[str] = []
        lines.append(
            f"{C.key('Entropy')}     : {C.value(f'{self.overall:.4f}')} bits/byte "
            f"({C.ok(self.overall_label) if self.overall < 6.8 else C.warn(self.overall_label)})"
        )
        lines.append(f"{C.key('Size')}        : {self.size} bytes")
        lines.append(f"{C.key('Distinct')}    : {self.distinct_bytes}/256 byte values")
        if self.most_common:
            rendered = ", ".join(f"0x{v:02x}×{c}" for v, c in self.most_common[:8])
            lines.append(f"{C.key('Top bytes')}   : {rendered}")
        series = [value for _, value in (self.windows or self.blocks)]
        if series:
            lines.append("")
            lines.append(C.title("Entropy profile (0 ────── 8 bits/byte)"))
            for row in render_sparkline(series, width=spark_width, ascii_only=ascii_only):
                lines.append("  " + C.ascii_bar(row))
            low = min(series)
            high = max(series)
            lines.append(
                f"  min {low:.3f} @ {min((o for o, v in (self.windows or self.blocks) if v == low), default=0)}"
                f"   max {high:.3f} @ {min((o for o, v in (self.windows or self.blocks) if v == high), default=0)}"
            )
        if show_blocks and self.blocks:
            lines.append("")
            lines.append(C.title("Block map"))
            for offset, value in self.blocks[:64]:
                bar = "█" * int(round(value / 8 * 32))
                lines.append(f"  {C.offset(f'0x{offset:08x}')}  {value:0.4f}  {C.ascii_bar(bar)}")
            if len(self.blocks) > 64:
                lines.append(C.dim(f"  … {len(self.blocks) - 64} more blocks"))
        return "\n".join(lines)


def build_report(
    data: bytes,
    block_size: int = 256,
    window: int = 1024,
    step: int = 256,
    with_blocks: bool = True,
    with_windows: bool = True,
) -> EntropyReport:
    """Build an :class:`EntropyReport` for *data*."""
    counts = byte_counts(data)
    overall = shannon_entropy(data, counts)
    distinct = sum(1 for count in counts if count)
    ordered = sorted(
        ((value, count) for value, count in enumerate(counts) if count),
        key=lambda item: -item[1],
    )
    return EntropyReport(
        size=len(data),
        overall=overall,
        overall_label=classify_entropy(overall),
        blocks=block_entropies(data, block_size) if with_blocks else [],
        windows=sliding_entropy(data, window, step) if with_windows else [],
        distinct_bytes=distinct,
        most_common=ordered[:8],
    )
