"""File-carving reconnaissance.

Carving (rebuilding files out of a raw blob) is out of scope for a
zero-dependency toolkit, but *finding* where embedded files start is not:
this module sweeps the buffer for known magic numbers located at a non-zero
offset and reports them as candidate embedded objects.  Useful for firmware
images, office documents, malware samples and "why is my PNG 40 MB?"
questions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .colors import C
from .magic import SIGNATURES, Signature

__all__ = ["CarveHit", "CarveResult", "carve", "TAIL_MAGIC"]


def carve(
    data: bytes,
    signatures: Optional[List[Signature]] = None,
    min_offset: int = 1,
    max_hits: int = 200,
    dedupe_distance: int = 1,
) -> "CarveResult":
    """Find embedded file signatures inside *data*.

    Args:
        data: buffer to sweep.
        signatures: rules to use (defaults to the built-in table).
        min_offset: ignore hits before this offset (``1`` skips the file
            header itself, which :mod:`hexscope.magic` already reports).
        max_hits: safety cap.
        dedupe_distance: collapse hits of the same rule closer than this.
    """
    if min_offset < 0:
        raise ValueError("min_offset must be >= 0")
    table = signatures or SIGNATURES
    hits: List[CarveHit] = []
    for signature in table:
        if signature.offset is not None and signature.offset != 0:
            continue  # anchored signatures are not meaningful when sweeping
        pattern = signature.pattern
        if len(pattern) < 4:
            # Two/three byte magics produce far too many false positives.
            continue
        start = 0
        while True:
            found = data.find(pattern, start)
            if found < 0:
                break
            start = found + dedupe_distance
            if found < min_offset:
                continue
            hits.append(
                CarveHit(
                    offset=found,
                    ext=signature.ext,
                    mime=signature.mime,
                    desc=signature.desc,
                    signature=signature.pattern.hex(),
                )
            )
            if len(hits) >= max_hits:
                break
        if len(hits) >= max_hits:
            break
    hits.sort(key=lambda hit: hit.offset)
    return CarveResult(hits=hits, size=len(data), capped=len(hits) >= max_hits)


@dataclass
class CarveHit:
    """One embedded-signature candidate."""

    offset: int
    ext: str
    mime: str
    desc: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "ext": self.ext,
            "mime": self.mime,
            "description": self.desc,
            "signature": self.signature,
        }


@dataclass
class CarveResult:
    """Outcome of :func:`carve`."""

    hits: List[CarveHit] = field(default_factory=list)
    size: int = 0
    capped: bool = False

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "capped": self.capped,
            "count": len(self.hits),
            "hits": [hit.to_dict() for hit in self.hits],
        }

    def render_text(self, limit: int = 100) -> str:
        if not self.hits:
            return C.warn("No embedded file signatures found.")
        lines: List[str] = []
        lines.append(C.title(f"Embedded candidates — {len(self.hits)} hit(s)"))
        for hit in self.hits[:limit]:
            lines.append(
                f"  {C.offset(f'0x{hit.offset:08x}')}  "
                f"{C.key(hit.ext.ljust(6))} {hit.desc}  {C.dim(hit.signature)}"
            )
        if len(self.hits) > limit:
            lines.append(C.dim(f"  … {len(self.hits) - limit} more hits"))
        if self.capped:
            lines.append(C.dim("  (hit cap reached — raise --max-hits for a full sweep)"))
        return "\n".join(lines)
