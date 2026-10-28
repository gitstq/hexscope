"""HexScope — a zero-dependency binary forensics workbench.

Everything runs on the Python standard library: no wheels to install, no
native extension, no network access, no telemetry.  Use it as a CLI::

    hexscope stats firmware.bin
    hexscope hex firmware.bin --offset 0x1000 --limit 256

…or as a library::

    from hexscope import identify, shannon_entropy, extract_strings

    with open("firmware.bin", "rb") as fh:
        blob = fh.read()
    identify(blob).best.signature.desc
"""

from __future__ import annotations

from .bindiff import DiffResult, diff_bytes
from .carve import CarveResult, carve
from .entropy import (
    EntropyReport,
    block_entropies,
    build_report,
    classify_entropy,
    shannon_entropy,
    sliding_entropy,
)
from .hexdump import DumpOptions, DumpRow, canonical_hexdump, hexdump, iter_rows
from .histogram import Histogram, build_histogram
from .magic import (
    SIGNATURES,
    IdentifyResult,
    Signature,
    identify,
    load_extra_signatures,
    sniff_text,
)
from .stats import FileStats, file_stats, human_size
from .strings import StringHit, StringResult, extract_strings

__version__ = "1.0.0"
__author__ = "HexScope contributors"
__license__ = "MIT"

__all__ = [
    # metadata
    "__version__",
    "__author__",
    "__license__",
    # hexdump
    "hexdump",
    "canonical_hexdump",
    "iter_rows",
    "DumpOptions",
    "DumpRow",
    # magic
    "identify",
    "IdentifyResult",
    "Signature",
    "SIGNATURES",
    "sniff_text",
    "load_extra_signatures",
    # entropy
    "shannon_entropy",
    "block_entropies",
    "sliding_entropy",
    "build_report",
    "classify_entropy",
    "EntropyReport",
    # strings
    "extract_strings",
    "StringHit",
    "StringResult",
    # histogram
    "build_histogram",
    "Histogram",
    # diff
    "diff_bytes",
    "DiffResult",
    # carve
    "carve",
    "CarveResult",
    # stats
    "file_stats",
    "FileStats",
    "human_size",
]
