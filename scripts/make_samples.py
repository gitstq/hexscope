#!/usr/bin/env python3
"""Generate the demo blob used by the README and by manual testing.

``python scripts/make_samples.py`` writes ``examples/sample.bin``: a
firmware-flavoured blob that contains a textual header, an embedded PNG
header, a random (high-entropy) region, a NUL-padded region and an embedded
ZIP header.  Every HexScope command produces something interesting on it.
"""

from __future__ import annotations

import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "examples")
OUT_FILE = os.path.join(OUT_DIR, "sample.bin")


def png_header(width: int = 8, height: int = 8) -> bytes:
    """A (non-renderable, but structurally valid) PNG prefix."""
    chunk = struct.pack(">II", width, height) + bytes([8, 6, 0, 0, 0])
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", len(chunk)) + b"IHDR" + chunk


def build(seed: int = 20261028) -> bytes:
    rng = random.Random(seed)
    parts = [
        b"FIRMWARE-IMAGE-V2\x00\x00",
        png_header(),
        bytes(rng.randrange(256) for _ in range(768)),  # encrypted-looking blob
        b"\x00" * 128,                                   # padding
        b"PK\x03\x04" + bytes(rng.randrange(256) for _ in range(256)),
        b"bootloader ready\n" * 4,
    ]
    return b"".join(parts)


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    blob = build()
    with open(OUT_FILE, "wb") as handle:
        handle.write(blob)
    print(f"wrote {OUT_FILE} ({len(blob)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
