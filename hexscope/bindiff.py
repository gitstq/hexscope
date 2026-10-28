"""Byte-level binary diff.

Text diff tools fall apart on binaries; this one never tries to be clever
about lines.  It scans both buffers, collects the differing regions and
merges regions that are closer together than ``context`` so the report stays
readable.  Each region can then be rendered as a side-by-side hex excerpt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .colors import C
from .hexdump import DumpOptions, hexdump

__all__ = ["DiffRegion", "DiffResult", "diff_bytes", "MAX_REGIONS"]


def diff_bytes(
    a: bytes,
    b: bytes,
    context: int = 32,
    max_regions: int = 64,
    max_scan: Optional[int] = None,
) -> "DiffResult":
    """Compare *a* and *b* byte by byte.

    Args:
        a: first buffer.
        b: second buffer.
        context: merge two differing regions when the gap between them is
            smaller than this many bytes.
        max_regions: stop collecting after this many regions.
        max_scan: only compare the first *max_scan* bytes.

    Returns:
        A :class:`DiffResult`.
    """
    if context < 0:
        raise ValueError("context must be >= 0")
    limit = min(len(a), len(b)) if max_scan is None else min(len(a), len(b), max_scan)
    raw: List[tuple[int, int]] = []
    index = 0
    while index < limit:
        if a[index] != b[index]:
            start = index
            index += 1
            while index < limit and a[index] != b[index]:
                index += 1
            raw.append((start, index))
            if len(raw) >= max_regions * 4:  # generous pre-merge cap
                break
        else:
            index += 1

    merged: List[tuple[int, int]] = []
    for start, end in raw:
        if merged and start - merged[-1][1] <= context:
            merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
        if len(merged) >= max_regions:
            break

    regions = [
        DiffRegion(
            offset=start,
            end=end,
            length=end - start,
            a_bytes=a[start:end],
            b_bytes=b[start:end],
        )
        for start, end in merged
    ]
    return DiffResult(
        size_a=len(a),
        size_b=len(b),
        scanned=limit,
        identical=not regions and len(a) == len(b),
        regions=regions,
        truncated=limit < min(len(a), len(b)),
    )


@dataclass
class DiffRegion:
    """A contiguous run of differing bytes."""

    offset: int
    end: int
    length: int
    a_bytes: bytes
    b_bytes: bytes

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "end": self.end,
            "length": self.length,
            "a_hex": self.a_bytes.hex(),
            "b_hex": self.b_bytes.hex(),
            "a_ascii": _gutter(self.a_bytes),
            "b_ascii": _gutter(self.b_bytes),
        }


@dataclass
class DiffResult:
    """Outcome of :func:`diff_bytes`."""

    size_a: int
    size_b: int
    scanned: int
    identical: bool
    regions: List[DiffRegion] = field(default_factory=list)
    truncated: bool = False

    @property
    def changed_bytes(self) -> int:
        return sum(region.length for region in self.regions)

    def to_dict(self) -> dict:
        return {
            "identical": self.identical,
            "size_a": self.size_a,
            "size_b": self.size_b,
            "scanned": self.scanned,
            "truncated": self.truncated,
            "changed_bytes": self.changed_bytes,
            "region_count": len(self.regions),
            "regions": [region.to_dict() for region in self.regions],
        }

    def render_text(self, excerpt: int = 64, show_hex: bool = True) -> str:
        lines: List[str] = []
        lines.append(
            f"{C.key('A')} : {self.size_a} bytes      {C.key('B')} : {self.size_b} bytes"
        )
        if self.identical:
            lines.append(C.ok("✔ Files are byte-for-byte identical."))
            return "\n".join(lines)
        if self.size_a != self.size_b:
            delta = self.size_b - self.size_a
            sign = "+" if delta > 0 else ""
            lines.append(
                C.warn(f"⚠ Size differs: {sign}{delta} bytes "
                       f"({self.size_a} → {self.size_b})")
            )
        lines.append(
            f"{C.key('Regions')} : {len(self.regions)} differing region(s), "
            f"{self.changed_bytes} changed byte(s) in the compared window"
        )
        if self.truncated:
            lines.append(C.dim("  (comparison window truncated by --max-scan)"))
        lines.append("")
        for position, region in enumerate(self.regions, start=1):
            lines.append(
                C.title(
                    f"[{position}] offset 0x{region.offset:08x} – 0x{region.end:08x} "
                    f"({region.length} bytes)"
                )
            )
            if show_hex:
                opts = DumpOptions(width=16, group=1)
                head_a = region.a_bytes[:excerpt]
                head_b = region.b_bytes[:excerpt]
                lines.append("  " + C.dim("A:"))
                for row in hexdump(head_a, start=region.offset, options=opts).splitlines():
                    lines.append("    " + row)
                lines.append("  " + C.dim("B:"))
                for row in hexdump(head_b, start=region.offset, options=opts).splitlines():
                    lines.append("    " + row)
                if region.length > excerpt:
                    lines.append(C.dim(f"    … {region.length - excerpt} more differing bytes"))
            lines.append("")
        return "\n".join(lines).rstrip()


def _gutter(chunk: bytes) -> str:
    return "".join(chr(v) if 0x20 <= v < 0x7F else "." for v in chunk)
