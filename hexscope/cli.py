"""Command line interface.

Sub-commands
------------
``hex``       canonical / configurable hex dump
``identify``  magic-number + text sniffing
``strings``   printable string extraction
``entropy``   Shannon entropy (whole file, blocks, sliding window)
``hist``      byte-value histogram
``diff``      byte-level binary diff
``carve``     embedded-file signature sweep
``stats``     one-shot file statistics
``report``    everything above, in one report

Every sub-command accepts ``--json`` / ``--md`` for machine consumption,
which makes HexScope usable as a CI step.
"""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from . import __version__
from .bindiff import diff_bytes
from .carve import carve
from .colors import C, set_color
from .entropy import build_report, render_sparkline
from .hexdump import DumpOptions, hexdump
from .histogram import build_histogram
from .magic import identify, load_extra_signatures
from .output import emit, kv_table, to_json
from .reader import read_bytes
from .stats import file_stats
from .strings import ENCODINGS, extract_strings

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2

#: Hard cap on rendered dump lines (protects your terminal).
DEFAULT_MAX_LINES = 512


def _int(value: str) -> int:
    """Parse ``10``, ``0x10``, ``1k``, ``4M`` into an int."""
    text = value.strip().replace("_", "")
    if not text:
        raise argparse.ArgumentTypeError("empty number")
    multiplier = 1
    suffix = text[-1].lower()
    if suffix in ("k", "m", "g"):
        multiplier = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[suffix]
        text = text[:-1]
    try:
        return int(text, 0) * multiplier
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hexscope",
        description="HexScope — zero-dependency binary forensics workbench.",
        epilog=(
            "examples:\n"
            "  hexscope stats firmware.bin\n"
            "  hexscope hex firmware.bin --offset 0x1000 --limit 256\n"
            "  hexscope entropy payload.bin --window 512 --ascii\n"
            "  hexscope diff a.bin b.bin --context 64\n"
            "  hexscope report mystery.bin --json\n"
            "  cat file | hexscope identify -\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"hexscope {__version__}")

    sub = parser.add_subparsers(dest="command", metavar="<command>")

    # Output switches are shared by every sub-command, so they live on a
    # parent parser and are attached after the positional argument.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json", action="store_true", help="emit JSON instead of human readable text"
    )
    common.add_argument("--md", action="store_true", help="emit Markdown instead of text")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    common.add_argument(
        "--color", dest="no_color", action="store_false", help="force ANSI colour"
    )
    common.set_defaults(no_color=None)

    # -- shared input options -------------------------------------------
    def add_input(sp: argparse.ArgumentParser, with_limit: bool = True) -> None:
        sp.add_argument("file", help="path to inspect, or '-' for stdin")
        sp.add_argument(
            "--offset", type=_int, default=0, help="skip this many bytes before reading"
        )
        if with_limit:
            sp.add_argument(
                "--limit",
                type=_int,
                default=None,
                help="read at most this many bytes (1k/4M suffixes supported)",
            )

    # -- hex -------------------------------------------------------------
    sp_hex = sub.add_parser("hex", parents=[common], help="hex dump")
    add_input(sp_hex)
    sp_hex.add_argument("--width", type=int, default=16, help="bytes per line (default 16)")
    sp_hex.add_argument("--group", type=int, default=1, help="bytes per group (default 1)")
    sp_hex.add_argument(
        "--base", type=int, default=16, choices=[2, 8, 10, 16], help="byte radix (default 16)"
    )
    sp_hex.add_argument("--uppercase", action="store_true", help="upper-case hex digits")
    sp_hex.add_argument("--no-ascii", action="store_true", help="hide the ASCII gutter")
    sp_hex.add_argument(
        "--pad", default=".", help="character used for non-printable bytes (default '.')"
    )
    sp_hex.add_argument(
        "--max-lines", type=int, default=DEFAULT_MAX_LINES, help="cap rendered lines"
    )

    # -- identify --------------------------------------------------------
    sp_id = sub.add_parser(
        "identify", aliases=["id"], parents=[common], help="magic-number identification"
    )
    add_input(sp_id)
    sp_id.add_argument(
        "--magic-file",
        help="extra signatures: 'offset|hex|ext|mime|description' per line",
    )

    # -- strings ---------------------------------------------------------
    sp_str = sub.add_parser("strings", parents=[common], help="extract printable strings")
    add_input(sp_str)
    sp_str.add_argument("--min-len", type=int, default=4, help="minimum run length (default 4)")
    sp_str.add_argument(
        "--encoding", default="ascii", choices=list(ENCODINGS), help="string encoding"
    )
    sp_str.add_argument("--pattern", help="keep only strings matching this regex")
    sp_str.add_argument("--max", type=int, default=None, help="stop after N hits")
    sp_str.add_argument("--no-offset", action="store_true", help="hide byte offsets")

    # -- entropy ---------------------------------------------------------
    sp_ent = sub.add_parser("entropy", parents=[common], help="Shannon entropy analysis")
    add_input(sp_ent)
    sp_ent.add_argument("--block", type=_int, default=256, help="block size for the block map")
    sp_ent.add_argument("--window", type=_int, default=1024, help="sliding window size")
    sp_ent.add_argument("--step", type=_int, default=256, help="sliding window step")
    sp_ent.add_argument("--no-blocks", action="store_true", help="skip the block map")
    sp_ent.add_argument("--no-windows", action="store_true", help="skip the sliding profile")
    sp_ent.add_argument("--width", type=int, default=64, help="sparkline width")
    sp_ent.add_argument("--ascii", action="store_true", help="ASCII-only sparkline")

    # -- hist ------------------------------------------------------------
    sp_hist = sub.add_parser("hist", parents=[common], help="byte-value histogram")
    add_input(sp_hist)
    sp_hist.add_argument("--top", type=int, default=16, help="show the N most common bytes")
    sp_hist.add_argument("--width", type=int, default=40, help="bar width")

    # -- diff ------------------------------------------------------------
    sp_diff = sub.add_parser("diff", parents=[common], help="byte-level binary diff")
    sp_diff.add_argument("a", help="first file ('-' for stdin)")
    sp_diff.add_argument("b", help="second file")
    sp_diff.add_argument("--context", type=int, default=32, help="merge gap in bytes")
    sp_diff.add_argument("--max-regions", type=int, default=64, help="cap reported regions")
    sp_diff.add_argument("--max-scan", type=_int, default=None, help="compare only N bytes")
    sp_diff.add_argument("--excerpt", type=int, default=64, help="bytes shown per region")
    sp_diff.add_argument("--no-hex", action="store_true", help="region list only")

    # -- carve -----------------------------------------------------------
    sp_carve = sub.add_parser("carve", parents=[common], help="embedded file signature sweep")
    add_input(sp_carve)
    sp_carve.add_argument("--min-offset", type=_int, default=1, help="ignore hits before this")
    sp_carve.add_argument("--max-hits", type=int, default=200, help="cap the sweep")

    # -- stats -----------------------------------------------------------
    sp_stats = sub.add_parser("stats", parents=[common], help="one-shot file statistics")
    add_input(sp_stats)

    # -- report ----------------------------------------------------------
    sp_report = sub.add_parser("report", parents=[common], help="full analysis in one pass")
    add_input(sp_report)
    sp_report.add_argument("--strings", type=int, default=20, help="strings to include")
    sp_report.add_argument("--min-len", type=int, default=5, help="minimum string length")
    sp_report.add_argument("--window", type=_int, default=1024, help="entropy window size")
    sp_report.add_argument("--step", type=_int, default=256, help="entropy window step")

    return parser


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _fmt(args: argparse.Namespace) -> str:
    if getattr(args, "json", False):
        return "json"
    if getattr(args, "md", False):
        return "md"
    return "text"


def _load(path: str, offset: int = 0, limit: Optional[int] = None) -> tuple[bytes, object]:
    data, source = read_bytes(path, offset=offset, limit=limit)
    if not data:
        raise SystemExit(f"hexscope: {source.label}: no data (empty input?)")
    return data, source


def _path_label(source) -> str:
    return source.label


# ---------------------------------------------------------------------------
# command implementations
# ---------------------------------------------------------------------------


def cmd_hex(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    options = DumpOptions(
        width=args.width,
        group=args.group,
        base=args.base,
        uppercase=args.uppercase,
        show_ascii=not args.no_ascii,
        pad_char=args.pad,
    )
    rows_total = (len(data) + args.width - 1) // args.width
    window = data
    truncated = False
    if rows_total > args.max_lines:
        window = data[: args.max_lines * args.width]
        truncated = True
    text = hexdump(window, start=args.offset, options=options)
    if _fmt(args) == "json":
        from .hexdump import iter_rows

        payload = {
            "source": _path_label(source),
            "offset": args.offset,
            "size": len(data),
            "rendered": len(window),
            "truncated": truncated,
            "rows": [row.to_dict() for row in iter_rows(window, start=args.offset, options=options)],
        }
        print(to_json(payload))
        return EXIT_OK
    if not options.color:
        print(text)
    else:
        print(text)
    if truncated:
        print(
            C.dim(
                f"\n… {rows_total - args.max_lines} more lines "
                f"(raise --max-lines to render them)"
            )
        )
    return EXIT_OK


def cmd_identify(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    extra = None
    if args.magic_file:
        with open(args.magic_file, "r", encoding="utf-8") as handle:
            extra = load_extra_signatures(handle.read())
    result = identify(data, extra=extra)
    if _fmt(args) == "json":
        payload = result.to_dict()
        payload["source"] = _path_label(source)
        print(to_json(payload))
        return EXIT_OK
    print(C.title(f"Identify — {_path_label(source)}"))
    print(result.render_text())
    return EXIT_OK


def cmd_strings(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    result = extract_strings(
        data,
        min_len=args.min_len,
        encoding=args.encoding,
        pattern=args.pattern,
        limit=args.max,
    )
    if _fmt(args) == "json":
        payload = result.to_dict()
        payload["source"] = _path_label(source)
        print(to_json(payload))
        return EXIT_OK
    if _fmt(args) == "md":
        from .output import markdown_table

        print(
            markdown_table(
                ["offset", "length", "encoding", "text"],
                [
                    [f"0x{hit.offset:08x}", hit.length, hit.encoding, hit.text]
                    for hit in result.hits
                ],
            )
        )
        return EXIT_OK
    print(C.title(f"Strings — {_path_label(source)} ({len(result.hits)} hits)"))
    print(result.render_text(show_offset=not args.no_offset))
    return EXIT_OK


def cmd_entropy(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    report = build_report(
        data,
        block_size=args.block,
        window=args.window,
        step=args.step,
        with_blocks=not args.no_blocks,
        with_windows=not args.no_windows,
    )
    if _fmt(args) == "json":
        payload = report.to_dict()
        payload["source"] = _path_label(source)
        print(to_json(payload))
        return EXIT_OK
    print(C.title(f"Entropy — {_path_label(source)}"))
    print(
        report.render_text(
            show_blocks=not args.no_blocks,
            spark_width=args.width,
            ascii_only=args.ascii,
        )
    )
    return EXIT_OK


def cmd_hist(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    histogram = build_histogram(data)
    if _fmt(args) == "json":
        payload = histogram.to_dict(top=args.top)
        payload["source"] = _path_label(source)
        print(to_json(payload))
        return EXIT_OK
    if _fmt(args) == "md":
        from .output import markdown_table

        info = histogram.to_dict(top=args.top)
        print(markdown_table(["byte", "char", "count", "pct"], [
            [row["byte"], row["char"], row["count"], row["pct"]] for row in info["top"]
        ]))
        return EXIT_OK
    print(C.title(f"Histogram — {_path_label(source)}"))
    print(histogram.render_text(top=args.top, width=args.width))
    return EXIT_OK


def cmd_diff(args: argparse.Namespace) -> int:
    first, source_a = _load(args.a, 0, args.max_scan)
    second, source_b = _load(args.b, 0, args.max_scan)
    result = diff_bytes(
        first,
        second,
        context=args.context,
        max_regions=args.max_regions,
        max_scan=args.max_scan,
    )
    if _fmt(args) == "json":
        payload = result.to_dict()
        payload["a"] = _path_label(source_a)
        payload["b"] = _path_label(source_b)
        print(to_json(payload))
        return EXIT_OK
    print(C.title(f"Diff — {_path_label(source_a)} vs {_path_label(source_b)}"))
    print(result.render_text(excerpt=args.excerpt, show_hex=not args.no_hex))
    return EXIT_OK if result.identical else EXIT_OK


def cmd_carve(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    result = carve(data, min_offset=args.min_offset, max_hits=args.max_hits)
    if _fmt(args) == "json":
        payload = result.to_dict()
        payload["source"] = _path_label(source)
        print(to_json(payload))
        return EXIT_OK
    if _fmt(args) == "md":
        from .output import markdown_table

        print(
            markdown_table(
                ["offset", "ext", "mime", "description", "signature"],
                [
                    [f"0x{hit.offset:08x}", hit.ext, hit.mime, hit.desc, hit.signature]
                    for hit in result.hits
                ],
            )
        )
        return EXIT_OK
    print(C.title(f"Carve — {_path_label(source)}"))
    print(result.render_text())
    return EXIT_OK


def cmd_stats(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    stats = file_stats(data, name=_path_label(source))
    if _fmt(args) == "json":
        print(to_json(stats.to_dict()))
        return EXIT_OK
    print(C.title(f"Stats — {_path_label(source)}"))
    print(stats.render_text())
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    data, source = _load(args.file, args.offset, args.limit)
    stats = file_stats(data, name=_path_label(source))
    result = identify(data)
    report = build_report(
        data,
        window=args.window,
        step=args.step,
        with_blocks=True,
        with_windows=True,
    )
    hits = extract_strings(data, min_len=args.min_len, limit=args.strings)
    histogram = build_histogram(data)
    carved = carve(data, max_hits=20)

    if _fmt(args) == "json":
        payload = {
            "source": _path_label(source),
            "stats": stats.to_dict(),
            "identify": result.to_dict(),
            "entropy": report.to_dict(),
            "strings": hits.to_dict(),
            "histogram": histogram.to_dict(top=8),
            "carve": carved.to_dict(),
        }
        print(to_json(payload))
        return EXIT_OK

    lines: List[str] = []
    lines.append(C.title(f"HexScope report — {_path_label(source)}"))
    lines.append("")
    lines.append(stats.render_text())
    lines.append("")
    lines.append(C.title("Identification"))
    lines.append(result.render_text())
    lines.append("")
    lines.append(report.render_text(show_blocks=False, spark_width=64))
    lines.append("")
    lines.append(C.title(f"Strings (first {len(hits.hits)})"))
    lines.append(hits.render_text(limit=args.strings))
    lines.append("")
    lines.append(C.title("Byte histogram"))
    lines.append(histogram.render_text(top=8, width=36))
    if carved.hits:
        lines.append("")
        lines.append(carved.render_text(limit=10))
    print("\n".join(lines))
    return EXIT_OK


COMMANDS = {
    "hex": cmd_hex,
    "identify": cmd_identify,
    "id": cmd_identify,
    "strings": cmd_strings,
    "entropy": cmd_entropy,
    "hist": cmd_hist,
    "diff": cmd_diff,
    "carve": cmd_carve,
    "stats": cmd_stats,
    "report": cmd_report,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entry point used by the console script and ``python -m hexscope``."""
    parser = build_parser()
    args = parser.parse_args(argv)
    # ``--no-color`` → False, ``--color`` → True, unset → auto-detect.
    no_color = getattr(args, "no_color", None)
    set_color(None if no_color is None else (not no_color))

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    handler = COMMANDS.get(args.command)
    if handler is None:  # pragma: no cover - argparse guards this
        parser.print_help()
        return EXIT_USAGE

    try:
        return handler(args)
    except FileNotFoundError as exc:
        print(f"hexscope: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except IsADirectoryError as exc:
        print(f"hexscope: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except ValueError as exc:
        print(f"hexscope: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - piping into head
        return EXIT_OK
    except KeyboardInterrupt:  # pragma: no cover
        print("hexscope: interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
