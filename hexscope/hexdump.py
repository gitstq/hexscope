"""Classic hex dump rendering (``xxd``-flavoured, but ours).

Output shape::

    00000000  89 50 4e 47 0d 0a 1a 0a  00 00 00 0d 49 48 44 52  |.PNG........IHDR|

The renderer is deterministic and dependency free, so it is safe to use in
tests, CI logs and JSON pipelines alike.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, List, Optional

from .colors import C

__all__ = ["DumpRow", "DumpOptions", "hexdump", "iter_rows", "canonical_hexdump"]

#: Byte values considered "printable" for the ASCII gutter.
PRINTABLE_MIN = 0x20
PRINTABLE_MAX = 0x7E


@dataclass
class DumpRow:
    """One rendered line of a hex dump."""

    offset: int
    bytes_: bytes
    ascii_: str

    def to_dict(self) -> dict:
        return {
            "offset": self.offset,
            "hex": self.bytes_.hex(),
            "ascii": self.ascii_,
        }


@dataclass
class DumpOptions:
    """Knobs for :func:`hexdump`."""

    width: int = 16
    group: int = 1
    base: int = 16
    uppercase: bool = False
    show_ascii: bool = True
    color: bool = True
    pad_char: str = "."

    def __post_init__(self) -> None:
        if self.width < 1:
            raise ValueError("width must be >= 1")
        if self.group < 1:
            raise ValueError("group must be >= 1")
        if self.base not in (2, 8, 10, 16):
            raise ValueError("base must be one of 2, 8, 10, 16")


def _format_offset(value: int, base: int) -> str:
    if base == 16:
        return f"{value:08x}"
    if base == 8:
        return f"{value:011o}"
    if base == 10:
        return f"{value:010d}"
    return f"{value:032b}"


def _format_byte(value: int, base: int, uppercase: bool) -> str:
    if base == 16:
        text = f"{value:02x}"
    elif base == 8:
        text = f"{value:03o}"
    elif base == 10:
        text = f"{value:03d}"
    else:
        text = f"{value:08b}"
    return text.upper() if uppercase else text


def _colorize_byte(value: int, text: str) -> str:
    """Pick a semantic colour for a single byte."""
    if value == 0x00:
        return C.hex_zero(text)
    if value == 0xFF:
        return C.hex_high(text)
    if PRINTABLE_MIN <= value <= PRINTABLE_MAX:
        return C.hex_printable(text)
    if value < PRINTABLE_MIN:
        return C.hex_control(text)
    return C.hex_high(text)


def _ascii_gutter(chunk: bytes, pad_char: str) -> str:
    out: List[str] = []
    for value in chunk:
        if PRINTABLE_MIN <= value <= PRINTABLE_MAX:
            out.append(chr(value))
        else:
            out.append(pad_char)
    return "".join(out)


def iter_rows(data: bytes, start: int = 0, options: Optional[DumpOptions] = None) -> Iterator[DumpRow]:
    """Yield :class:`DumpRow` objects for *data*.

    Args:
        data: bytes to render.
        start: base offset added to every row (for windowed dumps).
        options: rendering knobs; defaults are used when omitted.
    """
    opts = options or DumpOptions()
    for index in range(0, len(data), opts.width):
        chunk = data[index : index + opts.width]
        yield DumpRow(
            offset=start + index,
            bytes_=chunk,
            ascii_=_ascii_gutter(chunk, opts.pad_char),
        )


def _token_width(base: int) -> int:
    """Printed width of a single byte token for a given radix."""
    return len(_format_byte(0, base, False))


def _row_width(opts: DumpOptions) -> int:
    """Printed width of a *full* hex column block (without ANSI codes)."""
    token = _token_width(opts.base)
    groups = (opts.width + opts.group - 1) // opts.group
    return opts.width * token + max(groups - 1, 0)


def _join_hex(chunk: bytes, opts: DumpOptions) -> str:
    """Format one row's bytes, grouping them and padding the last row."""
    tokens: List[str] = []
    for value in chunk:
        text = _format_byte(value, opts.base, opts.uppercase)
        if opts.color:
            text = _colorize_byte(value, text)
        tokens.append(text)
    groups = [
        "".join(tokens[index : index + opts.group])
        for index in range(0, len(tokens), opts.group)
    ]
    body = " ".join(groups)
    # Pad short (final) rows so the ASCII gutter stays aligned.
    pad = _row_width(opts) - len(_strip_ansi(body))
    if pad > 0:
        body += " " * pad
    return body


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences (used for width calculations)."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def hexdump(
    data: bytes,
    start: int = 0,
    options: Optional[DumpOptions] = None,
) -> str:
    """Render *data* as a full hex dump string."""
    opts = options or DumpOptions()
    lines: List[str] = []
    for row in iter_rows(data, start=start, options=opts):
        offset = _format_offset(row.offset, opts.base)
        if opts.color:
            offset = C.offset(offset)
        body = _join_hex(row.bytes_, opts)
        line = f"{offset}  {body}"
        if opts.show_ascii:
            gutter = row.ascii_
            if opts.color:
                gutter = C.ascii_bar(gutter)
            line += f"  |{gutter}|"
        lines.append(line.rstrip())
    return "\n".join(lines)


def canonical_hexdump(data: bytes, start: int = 0, width: int = 16) -> str:
    """Colour-free canonical dump (used by tests and ``--no-color`` output)."""
    return hexdump(
        data,
        start=start,
        options=DumpOptions(width=width, group=1, color=False, show_ascii=True),
    )
