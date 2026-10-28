"""Self-contained test suite (standard library ``unittest`` only).

Run it with any of::

    python -m unittest discover -s tests -v
    python tests/test_hexscope.py
    python -m hexscope --version     # smoke test for the package itself
"""

from __future__ import annotations

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hexscope import (  # noqa: E402
    build_histogram,
    build_report,
    canonical_hexdump,
    carve,
    diff_bytes,
    extract_strings,
    file_stats,
    hexdump,
    identify,
    load_extra_signatures,
    shannon_entropy,
)
from hexscope.cli import main  # noqa: E402
from hexscope.colors import set_color  # noqa: E402
from hexscope.hexdump import DumpOptions  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + b"IHDR" + b"\x01\x02\x03\x04"
ZIP = b"PK\x03\x04" + b"\x14\x00\x00\x00" + b"\x08\x00" + b"\x00" * 8
PDF = b"%PDF-1.7\n" + b"1 0 obj\n<<>>\nendobj\n" * 4
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00"
TEXT = b"Hello HexScope!\nThis is plain ASCII text.\n" * 4


class TestEntropy(unittest.TestCase):
    def test_uniform_data_is_zero(self):
        self.assertAlmostEqual(shannon_entropy(b"A" * 4096), 0.0, places=9)

    def test_two_symbols_is_one_bit(self):
        self.assertAlmostEqual(shannon_entropy(b"AB" * 4096), 1.0, places=6)

    def test_all_byte_values_is_eight_bits(self):
        data = bytes(range(256)) * 16
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=6)

    def test_empty_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_report_shape(self):
        report = build_report(bytes(range(256)) * 8, block_size=256, window=512, step=256)
        self.assertEqual(report.size, 2048)
        self.assertGreater(report.overall, 7.5)
        self.assertEqual(report.distinct_bytes, 256)
        self.assertTrue(report.blocks)
        self.assertTrue(report.windows)
        payload = json.loads(json.dumps(report.to_dict()))
        self.assertIn("entropy", payload)
        self.assertEqual(payload["label"], "encrypted/random")

    def test_text_entropy_is_low(self):
        report = build_report(TEXT, with_blocks=False, with_windows=False)
        self.assertLess(report.overall, 5.5)


class TestHexdump(unittest.TestCase):
    def test_canonical_layout(self):
        out = canonical_hexdump(bytes(range(16)), width=16)
        first = out.splitlines()[0]
        self.assertTrue(first.startswith("00000000  "))
        self.assertIn("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f", first)
        self.assertIn("|................|", first)

    def test_ascii_gutter(self):
        out = hexdump(b"Hello!", options=DumpOptions(color=False))
        self.assertIn("|Hello!|", out)

    def test_start_offset(self):
        out = hexdump(b"\x01\x02", start=0x1000, options=DumpOptions(color=False))
        self.assertTrue(out.startswith("00001000"))

    def test_grouping(self):
        out = hexdump(bytes(range(4)), options=DumpOptions(width=4, group=2, color=False))
        self.assertIn("0001 0203", out)

    def test_base_radix(self):
        out = hexdump(b"\xff", options=DumpOptions(base=2, color=False, show_ascii=False))
        self.assertIn("11111111", out)

    def test_row_alignment(self):
        out = canonical_hexdump(b"abc", width=16)
        line = out.splitlines()[0]
        self.assertIn("|abc", line)
        # the gutter must start at a fixed column regardless of row length
        # 8 (offset) + 2 + 16*2 (hex) + 15 (separators) + 2
        self.assertEqual(line.index("|"), 59)

    def test_invalid_options(self):
        with self.assertRaises(ValueError):
            DumpOptions(width=0)
        with self.assertRaises(ValueError):
            DumpOptions(base=7)


class TestIdentify(unittest.TestCase):
    def test_png(self):
        result = identify(PNG)
        self.assertIsNotNone(result.best)
        self.assertEqual(result.best.signature.ext, "png")
        self.assertEqual(result.best.offset, 0)

    def test_zip(self):
        self.assertEqual(identify(ZIP).best.signature.ext, "zip")

    def test_pdf(self):
        self.assertEqual(identify(PDF).best.signature.ext, "pdf")

    def test_elf(self):
        self.assertEqual(identify(ELF).best.signature.ext, "elf")

    def test_plain_text(self):
        result = identify(TEXT)
        self.assertEqual(result.text_guess, "plain text")
        self.assertEqual(result.encoding, "utf-8")

    def test_json_sniff(self):
        result = identify(b'{"a": 1, "b": [2, 3]}')
        self.assertEqual(result.text_guess, "json")

    def test_shebang(self):
        result = identify(b"#!/usr/bin/env python3\nprint(1)\n")
        self.assertTrue(result.text_guess.startswith("script"))

    def test_utf16_bom(self):
        result = identify(b"\xff\xfe" + "hi there".encode("utf-16-le"))
        self.assertEqual(result.encoding, "utf-16-le")

    def test_unknown_binary(self):
        result = identify(bytes(range(256)))
        # no *anchored* signature should win on raw noise
        self.assertIsNone(result.text_guess)

    def test_custom_signatures(self):
        rules = load_extra_signatures("0|de ad be ef|bin|application/x-test|Test magic\n")
        data = b"\xde\xad\xbe\xef" + b"\x00" * 8
        result = identify(data, extra=rules)
        self.assertEqual(result.best.signature.ext, "bin")
        self.assertEqual(result.best.signature.desc, "Test magic")

    def test_floating_signature(self):
        rules = load_extra_signatures("*|ca fe ba be|bin|application/x-test|Floating\n")
        data = b"\x00" * 64 + b"\xca\xfe\xba\xbe"
        self.assertIsNotNone(identify(data, extra=rules).best)


class TestStrings(unittest.TestCase):
    def test_ascii_runs(self):
        data = b"\x00\x00Hello World!\x00\x00short\x00"
        hits = extract_strings(data, min_len=5).hits
        self.assertEqual([hit.text for hit in hits], ["Hello World!", "short"])
        self.assertEqual(hits[0].offset, 2)

    def test_min_len_filter(self):
        hits = extract_strings(b"abcdefgh", min_len=4).hits
        self.assertEqual(len(hits), 1)
        self.assertEqual(len(extract_strings(b"abc", min_len=4).hits), 0)

    def test_utf16le(self):
        data = "Hello UTF16".encode("utf-16-le")
        hits = extract_strings(data, min_len=4, encoding="utf-16-le").hits
        self.assertTrue(any("Hello UTF16" in hit.text for hit in hits))

    def test_pattern_filter(self):
        data = b"\x00alpha\x00\x00beta\x00\x00gamma\x00"
        hits = extract_strings(data, min_len=4, pattern=r"^g").hits
        self.assertEqual([hit.text for hit in hits], ["gamma"])

    def test_limit(self):
        hits = extract_strings(b"\x00aaaa\x00\x00bbbb\x00\x00cccc\x00", min_len=4, limit=2).hits
        self.assertEqual([hit.text for hit in hits], ["aaaa", "bbbb"])

    def test_bad_encoding(self):
        with self.assertRaises(ValueError):
            extract_strings(b"data", encoding="utf-64")


class TestHistogram(unittest.TestCase):
    def test_counts(self):
        hist = build_histogram(b"AAB")
        self.assertEqual(hist.counts[0x41], 2)
        self.assertEqual(hist.counts[0x42], 1)
        self.assertEqual(hist.size, 3)

    def test_top_and_categories(self):
        hist = build_histogram(b"a" * 10 + b"\x00" * 5)
        self.assertEqual(hist.top(1)[0][0], 0x61)
        names = [name for name, _, _ in hist.by_category()]
        self.assertIn("lower a-z", names)
        self.assertIn("NUL", names)

    def test_coverage(self):
        hist = build_histogram(bytes(range(256)))
        self.assertAlmostEqual(hist.coverage(256), 1.0, places=6)


class TestDiff(unittest.TestCase):
    def test_identical(self):
        result = diff_bytes(b"same", b"same")
        self.assertTrue(result.identical)
        self.assertEqual(result.regions, [])

    def test_single_region(self):
        result = diff_bytes(b"AAAABBBB", b"AAAAXXXX")
        self.assertFalse(result.identical)
        self.assertEqual(len(result.regions), 1)
        self.assertEqual(result.regions[0].offset, 4)
        self.assertEqual(result.changed_bytes, 4)

    def test_context_merging(self):
        a = bytearray(64)
        b = bytearray(64)
        b[0] = 1
        b[8] = 1
        merged = diff_bytes(bytes(a), bytes(b), context=32)
        self.assertEqual(len(merged.regions), 1)
        split = diff_bytes(bytes(a), bytes(b), context=0)
        self.assertEqual(len(split.regions), 2)

    def test_size_mismatch(self):
        result = diff_bytes(b"abc", b"abcdef")
        self.assertEqual(result.size_a, 3)
        self.assertEqual(result.size_b, 6)

    def test_max_scan(self):
        a = b"AAAA" + b"Z" * 100
        b = b"AAAA" + b"Y" * 100
        result = diff_bytes(a, b, max_scan=4)
        self.assertTrue(result.identical)
        self.assertTrue(result.truncated)


class TestCarve(unittest.TestCase):
    def test_embedded_png(self):
        blob = b"HEADER" + b"\x00" * 8 + PNG
        hits = carve(blob).hits
        self.assertTrue(any(hit.ext == "png" for hit in hits))
        self.assertEqual([hit.offset for hit in hits if hit.ext == "png"][0], 14)

    def test_min_offset_zero_includes_header(self):
        hits = carve(PNG, min_offset=0).hits
        self.assertEqual(hits[0].offset, 0)

    def test_no_false_positive_on_text(self):
        self.assertEqual(carve(TEXT).hits, [])

    def test_hit_cap(self):
        blob = (PNG + b"\x00" * 4) * 50
        result = carve(blob, max_hits=5)
        self.assertTrue(result.capped)
        self.assertLessEqual(len(result.hits), 5)


class TestStats(unittest.TestCase):
    def test_text_verdict(self):
        stats = file_stats(TEXT, name="t.txt")
        self.assertEqual(stats.size, len(TEXT))
        self.assertIn("plain text", stats.verdict)
        self.assertEqual(stats.line_endings.get("LF"), TEXT.count(b"\n"))
        self.assertEqual(len(stats.sha256), 64)

    def test_binary_verdict(self):
        stats = file_stats(bytes(range(256)) * 32, name="r.bin")
        self.assertIn("encrypted or compressed", stats.verdict)

    def test_empty_file(self):
        stats = file_stats(b"", name="empty")
        self.assertEqual(stats.verdict, "empty file")

    def test_json_serialisable(self):
        payload = json.loads(json.dumps(file_stats(PNG, name="p.png").to_dict()))
        self.assertEqual(payload["kind"], "PNG image")


class TestCLI(unittest.TestCase):
    def setUp(self):
        set_color(False)
        self.tmp = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_tmp")
        os.makedirs(self.tmp, exist_ok=True)
        self.bin_path = os.path.join(self.tmp, "sample.bin")
        with open(self.bin_path, "wb") as handle:
            handle.write(b"HEADER!" + b"\x00" * 4 + PNG + TEXT)

    def _run(self, argv):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = main(argv)
        return code, buffer.getvalue()

    def test_help(self):
        code, out = self._run([])
        self.assertEqual(code, 2)
        self.assertIn("HexScope", out)

    def test_version(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("hexscope", buffer.getvalue())

    def test_stats_command(self):
        code, out = self._run(["stats", self.bin_path])
        self.assertEqual(code, 0)
        self.assertIn("SHA-256", out)

    def test_hex_command(self):
        code, out = self._run(["hex", self.bin_path, "--limit", "32"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("00000000"))

    def test_identify_json(self):
        code, out = self._run(["identify", self.bin_path, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertTrue(payload["matched"])

    def test_strings_command(self):
        code, out = self._run(["strings", self.bin_path, "--min-len", "6"])
        self.assertEqual(code, 0)
        self.assertIn("Hello HexScope!", out)

    def test_entropy_command(self):
        code, out = self._run(["entropy", self.bin_path, "--ascii", "--width", "32"])
        self.assertEqual(code, 0)
        self.assertIn("bits/byte", out)

    def test_hist_command(self):
        code, out = self._run(["hist", self.bin_path, "--top", "4"])
        self.assertEqual(code, 0)
        self.assertIn("Byte histogram", out)

    def test_carve_command(self):
        code, out = self._run(["carve", self.bin_path])
        self.assertEqual(code, 0)
        self.assertIn("png", out)

    def test_diff_command(self):
        second = os.path.join(self.tmp, "sample2.bin")
        with open(second, "wb") as handle:
            handle.write(b"HEADER?" + b"\x00" * 4 + PNG + TEXT)
        code, out = self._run(["diff", self.bin_path, second, "--no-hex"])
        self.assertEqual(code, 0)
        self.assertIn("differing region", out)

    def test_report_json(self):
        code, out = self._run(["report", self.bin_path, "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        for key in ("stats", "identify", "entropy", "strings", "histogram", "carve"):
            self.assertIn(key, payload)

    def test_missing_file(self):
        code, _ = self._run(["stats", os.path.join(self.tmp, "nope.bin")])
        self.assertEqual(code, 1)

    def test_stdin(self):
        buffer = io.StringIO()
        stdin = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(PNG))
        try:
            with redirect_stdout(buffer):
                code = main(["identify", "-"])
        finally:
            sys.stdin = stdin
        self.assertEqual(code, 0)
        self.assertIn("PNG", buffer.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
