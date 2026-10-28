"""One-shot file statistics: the "what even is this file?" command."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .colors import C
from .entropy import build_report, shannon_entropy
from .histogram import build_histogram
from .magic import identify

__all__ = ["FileStats", "file_stats", "human_size"]


def human_size(size: int) -> str:
    """Human readable size (binary units)."""
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TiB"


@dataclass
class FileStats:
    """Aggregate view of a file/buffer."""

    name: Optional[str]
    size: int
    sha256: str
    md5: str
    entropy: float
    entropy_label: str
    printable_ratio: float
    null_ratio: float
    control_ratio: float
    high_ratio: float
    kind: Optional[str]
    mime: Optional[str]
    encoding: Optional[str]
    line_endings: Dict[str, int] = field(default_factory=dict)
    distinct_bytes: int = 0
    top_bytes: List[tuple[int, int]] = field(default_factory=list)
    verdict: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "size": self.size,
            "size_human": human_size(self.size),
            "sha256": self.sha256,
            "md5": self.md5,
            "entropy": round(self.entropy, 6),
            "entropy_label": self.entropy_label,
            "printable_ratio": round(self.printable_ratio, 6),
            "null_ratio": round(self.null_ratio, 6),
            "control_ratio": round(self.control_ratio, 6),
            "high_ratio": round(self.high_ratio, 6),
            "kind": self.kind,
            "mime": self.mime,
            "encoding": self.encoding,
            "line_endings": self.line_endings,
            "distinct_bytes": self.distinct_bytes,
            "top_bytes": [
                {"byte": f"0x{v:02x}", "count": c} for v, c in self.top_bytes
            ],
            "verdict": self.verdict,
        }

    def render_text(self) -> str:
        pairs: List[tuple[str, Any]] = [
            ("Name", self.name or "<memory>"),
            ("Size", f"{self.size} bytes ({human_size(self.size)})"),
            ("SHA-256", self.sha256),
            ("MD5", self.md5),
            ("Type", self.kind or "unknown"),
            ("MIME", self.mime or "application/octet-stream"),
            ("Encoding", self.encoding or "—"),
            ("Entropy", f"{self.entropy:.4f} bits/byte ({self.entropy_label})"),
            ("Printable", f"{self.printable_ratio * 100:.2f}%"),
            ("NUL bytes", f"{self.null_ratio * 100:.2f}%"),
            ("Control", f"{self.control_ratio * 100:.2f}%"),
            ("High bytes", f"{self.high_ratio * 100:.2f}%"),
            ("Distinct", f"{self.distinct_bytes}/256"),
        ]
        from .output import kv_table

        lines = [kv_table(pairs, pad=10)]
        if self.line_endings:
            rendered = ", ".join(
                f"{name}×{count}" for name, count in sorted(self.line_endings.items(), key=lambda i: -i[1])
            )
            lines.append(f"{C.key('Line ends'.ljust(10))} : {rendered}")
        if self.top_bytes:
            rendered = ", ".join(f"0x{v:02x}×{c}" for v, c in self.top_bytes[:8])
            lines.append(f"{C.key('Top bytes'.ljust(10))} : {rendered}")
        lines.append("")
        lines.append(C.ok("Verdict") + f"  : {self.verdict}")
        return "\n".join(lines)


def file_stats(data: bytes, name: Optional[str] = None) -> FileStats:
    """Compute :class:`FileStats` for *data*."""
    size = len(data)
    counts = [0] * 256
    printable = 0
    nulls = 0
    control = 0
    high = 0
    for value in data:
        counts[value] += 1
        if 0x20 <= value < 0x7F:
            printable += 1
        elif value == 0x00:
            nulls += 1
        elif value < 0x20 or value == 0x7F:
            control += 1
        if value >= 0x80:
            high += 1

    total = size or 1
    report = build_report(data, with_blocks=False, with_windows=False)
    result = identify(data)
    best = result.best
    kind = best.signature.desc if best else result.text_guess
    mime = best.signature.mime if best else (
        "text/plain" if (result.text_guess or "").startswith(("plain", "json", "xml", "html", "script", "text"))
        else "application/octet-stream"
    )

    endings: Dict[str, int] = {}
    if size:
        crlf = data.count(b"\r\n")
        lf = data.count(b"\n") - crlf
        cr = data.count(b"\r") - crlf
        if crlf:
            endings["CRLF"] = crlf
        if lf:
            endings["LF"] = lf
        if cr:
            endings["CR"] = cr

    verdict = _verdict(
        size=size,
        entropy=report.overall,
        label=report.overall_label,
        printable_ratio=printable / total,
        null_ratio=nulls / total,
        kind=kind,
    )

    return FileStats(
        name=name,
        size=size,
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        entropy=report.overall,
        entropy_label=report.overall_label,
        printable_ratio=printable / total,
        null_ratio=nulls / total,
        control_ratio=control / total,
        high_ratio=high / total,
        kind=kind,
        mime=mime,
        encoding=result.encoding,
        line_endings=endings,
        distinct_bytes=report.distinct_bytes,
        top_bytes=report.most_common[:8],
        verdict=verdict,
    )


def _verdict(
    size: int,
    entropy: float,
    label: str,
    printable_ratio: float,
    null_ratio: float,
    kind: Optional[str],
) -> str:
    """Compose the one-line human summary shown by ``hexscope stats``."""
    if size == 0:
        return "empty file"
    if printable_ratio > 0.95:
        base = "plain text"
    elif entropy > 7.6:
        base = "encrypted or compressed payload"
    elif entropy > 6.8:
        base = "likely compressed data"
    elif null_ratio > 0.25:
        base = "sparse / padded binary (lots of NUL)"
    else:
        base = "structured binary"
    if kind:
        return f"{base} — identified as {kind}"
    return f"{base} — no known signature ({label} entropy)"
