"""Magic-number (file signature) identification, hand-rolled.

Unlike ``libmagic`` we ship the signature table *inside* the package as plain
Python data: no shared library, no data file, no network.  Every entry is:

    Signature(offset, pattern, extensions, mime, description)

where ``offset`` is either an absolute byte offset or ``None`` meaning "search
within the first :data:`SEARCH_WINDOW` bytes" (needed for container formats
such as ISO-BMFF / MP4 whose ``ftyp`` box sits at offset 4, or tar whose
``ustar`` marker lives at offset 257).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .colors import C

__all__ = [
    "Signature",
    "SIGNATURES",
    "Match",
    "identify",
    "identify_stream",
    "sniff_text",
    "load_extra_signatures",
]

#: How far into the file we look for "floating" signatures.
SEARCH_WINDOW = 4096


@dataclass(frozen=True)
class Signature:
    """A single magic-number rule."""

    pattern: bytes
    ext: str
    mime: str
    desc: str
    offset: Optional[int] = 0

    def matches(self, data: bytes) -> Optional[int]:
        """Return the offset where the signature starts, or ``None``."""
        if self.offset is not None:
            start = self.offset
            if start + len(self.pattern) > len(data):
                return None
            if data[start : start + len(self.pattern)] == self.pattern:
                return start
            return None
        window = data[:SEARCH_WINDOW]
        found = window.find(self.pattern)
        return found if found >= 0 else None


def _sig(pattern: bytes, ext: str, mime: str, desc: str, offset: Optional[int] = 0) -> Signature:
    return Signature(pattern=pattern, ext=ext, mime=mime, desc=desc, offset=offset)


#: The built-in table.  Ordered: more specific signatures come first.
SIGNATURES: List[Signature] = [
    # -- images ----------------------------------------------------------
    _sig(b"\x89PNG\r\n\x1a\n", "png", "image/png", "PNG image"),
    _sig(b"\xff\xd8\xff", "jpg", "image/jpeg", "JPEG image"),
    _sig(b"GIF87a", "gif", "image/gif", "GIF image (87a)"),
    _sig(b"GIF89a", "gif", "image/gif", "GIF image (89a)"),
    _sig(b"BM", "bmp", "image/bmp", "BMP image"),
    _sig(b"RIFF", "webp", "image/webp", "RIFF container (WebP/WAV/AVI)"),
    _sig(b"\x00\x00\x01\x00", "ico", "image/x-icon", "ICO icon"),
    _sig(b"II*\x00", "tif", "image/tiff", "TIFF image (little endian)"),
    _sig(b"MM\x00*", "tif", "image/tiff", "TIFF image (big endian)"),
    _sig(b"8BPS", "psd", "image/vnd.adobe.photoshop", "Adobe Photoshop document"),
    _sig(b"\x47\x49\x46", "gif", "image/gif", "GIF image (generic)"),
    _sig(b"q\x00\x00", "icns", "image/x-icns", "Apple icon"),
    _sig(b"\xd7\xcd\xc6\x9a", "wmf", "image/wmf", "Windows Metafile"),
    _sig(b"P1\n", "pbm", "image/x-portable-bitmap", "Netpbm ASCII bitmap"),
    _sig(b"P5\n", "pgm", "image/x-portable-graymap", "Netpbm graymap"),
    _sig(b"P6\n", "ppm", "image/x-portable-pixmap", "Netpbm pixmap"),
    _sig(b"\x1f\x8b", "gz", "application/gzip", "gzip stream", None),
    # -- audio / video ---------------------------------------------------
    _sig(b"ID3", "mp3", "audio/mpeg", "MP3 audio (ID3v2 tag)"),
    _sig(b"\xff\xfb", "mp3", "audio/mpeg", "MP3 audio (MPEG-1 Layer III)"),
    _sig(b"\xff\xf3", "mp3", "audio/mpeg", "MP3 audio (MPEG-2 Layer III)"),
    _sig(b"OggS", "ogg", "audio/ogg", "Ogg container"),
    _sig(b"fLaC", "flac", "audio/flac", "FLAC audio"),
    _sig(b"MThd", "mid", "audio/midi", "MIDI sequence"),
    _sig(b"ftyp", "mp4", "video/mp4", "ISO-BMFF container (MP4/MOV/M4A)", None),
    _sig(b"\x1aE\xdf\xa3", "mkv", "video/x-matroska", "Matroska / WebM container"),
    _sig(b"FLV\x01", "flv", "video/x-flv", "Flash video"),
    _sig(b"RIFFAVI ", "avi", "video/x-msvideo", "AVI video", 0),
    # -- archives / compression ------------------------------------------
    _sig(b"PK\x03\x04", "zip", "application/zip", "ZIP archive (also jar/docx/xlsx/apk)"),
    _sig(b"PK\x05\x06", "zip", "application/zip", "ZIP archive (empty)", None),
    _sig(b"PK\x07\x08", "zip", "application/zip", "ZIP archive (spanned)", None),
    _sig(b"Rar!\x1a\x07", "rar", "application/x-rar-compressed", "RAR archive"),
    _sig(b"7z\xbc\xaf\x27\x1c", "7z", "application/x-7z-compressed", "7-Zip archive"),
    _sig(b"\xfd7zXZ\x00", "xz", "application/x-xz", "XZ compressed stream"),
    _sig(b"BZh", "bz2", "application/x-bzip2", "bzip2 compressed stream"),
    _sig(b"\x28\xb5\x2f\xfd", "zst", "application/zstd", "Zstandard frame"),
    _sig(b"\x04\x22\x4d\x18", "lz4", "application/x-lz4", "LZ4 frame"),
    _sig(b"\x1f\x9d", "Z", "application/x-compress", "UNIX compress (LZW)"),
    _sig(b"\x1f\xa0", "Z", "application/x-compress", "UNIX compress (LZH)"),
    _sig(b"ustar", "tar", "application/x-tar", "POSIX tar archive", 257),
    _sig(b"!<arch>\n", "ar", "application/x-archive", "UNIX ar archive"),
    _sig(b"MSCF", "cab", "application/vnd.ms-cab-compressed", "Microsoft CAB archive"),
    _sig(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "doc", "application/msword", "OLE2 compound document (doc/xls/ppt/msi)"),
    _sig(b"Composite Document File", "doc", "application/msword", "OLE2 compound document (text marker)", None),
    _sig(b"\xed\xab\xee\xdb", "rpm", "application/x-rpm", "RPM package"),
    _sig(b"!<arch>\ndebian", "deb", "application/x-debian-package", "Debian package"),
    # -- executables / bytecode ------------------------------------------
    _sig(b"\x7fELF", "elf", "application/x-executable", "ELF executable / shared object"),
    _sig(b"MZ", "exe", "application/x-dosexec", "DOS/PE executable (MZ header)"),
    _sig(b"\xcf\xfa\xed\xfe", "macho", "application/x-mach-binary", "Mach-O binary (64-bit LE)"),
    _sig(b"\xce\xfa\xed\xfe", "macho", "application/x-mach-binary", "Mach-O binary (32-bit LE)"),
    _sig(b"\xca\xfe\xba\xbe", "class", "application/java-vm", "Java class file / Mach-O fat binary"),
    _sig(b"dex\n035\x00", "dex", "application/x-dex", "Android DEX bytecode"),
    _sig(b"dex\n037\x00", "dex", "application/x-dex", "Android DEX bytecode (037)"),
    _sig(b"dex\n038\x00", "dex", "application/x-dex", "Android DEX bytecode (038)"),
    _sig(b"\x00asm", "wasm", "application/wasm", "WebAssembly module"),
    _sig(b"\x16\x03\x01", "pyc", "application/x-python-code", "ambiguous (TLS record / data)"),
    # -- documents / data -------------------------------------------------
    _sig(b"%PDF", "pdf", "application/pdf", "PDF document"),
    _sig(b"%!PS", "ps", "application/postscript", "PostScript document"),
    _sig(b"SQLite format 3\x00", "sqlite", "application/x-sqlite3", "SQLite 3 database"),
    _sig(b"\x00\x01\x00\x00Standard Jet DB", "mdb", "application/x-msaccess", "Microsoft Access database"),
    _sig(b"PAR1", "parquet", "application/vnd.apache.parquet", "Apache Parquet"),
    _sig(b"ORC", "orc", "application/x-orc", "Apache ORC file"),
    _sig(b"Obj\x01", "avro", "application/x-avro", "Apache Avro container"),
    _sig(b"\x89HDF\r\n\x1a\n", "hdf5", "application/x-hdf5", "HDF5 dataset"),
    _sig(b"\x0f\x0b\x00\x00", "bson", "application/bson", "BSON document (ambiguous)"),
    # -- fonts ------------------------------------------------------------
    _sig(b"\x00\x01\x00\x00\x00", "ttf", "font/ttf", "TrueType font"),
    _sig(b"true", "ttf", "font/ttf", "TrueType font (true marker)"),
    _sig(b"OTTO", "otf", "font/otf", "OpenType font (CFF)"),
    _sig(b"wOFF", "woff", "font/woff", "WOFF font"),
    _sig(b"wOF2", "woff2", "font/woff2", "WOFF2 font"),
    # -- keys / certificates ----------------------------------------------
    _sig(b"-----BEGIN CERTIFICATE", "pem", "application/x-x509-ca-cert", "PEM certificate"),
    _sig(b"-----BEGIN RSA PRIVATE KEY", "pem", "application/x-pem-file", "PEM RSA private key"),
    _sig(b"-----BEGIN PRIVATE KEY", "pem", "application/x-pem-file", "PEM private key (PKCS#8)"),
    _sig(b"-----BEGIN OPENSSH PRIVATE KEY", "key", "application/x-openssh-key", "OpenSSH private key"),
    _sig(b"ssh-rsa ", "pub", "text/plain", "SSH public key (ssh-rsa)", None),
    _sig(b"\x30\x82", "der", "application/x-x509-ca-cert", "DER/ASN.1 sequence (ambiguous)"),
    _sig(b"PuTTY-User-Key-File-", "ppk", "application/x-putty-key", "PuTTY private key"),
]


@dataclass
class Match:
    """A signature hit."""

    signature: Signature
    offset: int
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "ext": self.signature.ext,
            "mime": self.signature.mime,
            "description": self.signature.desc,
            "offset": self.offset,
            "signature": self.signature.pattern.hex(),
            "confidence": round(self.confidence, 3),
        }


@dataclass
class IdentifyResult:
    """Result of :func:`identify`."""

    matches: List[Match] = field(default_factory=list)
    text_guess: Optional[str] = None
    encoding: Optional[str] = None

    @property
    def best(self) -> Optional[Match]:
        return self.matches[0] if self.matches else None

    def to_dict(self) -> dict:
        best = self.best
        return {
            "matched": best is not None,
            "best": best.to_dict() if best else None,
            "matches": [match.to_dict() for match in self.matches],
            "text_guess": self.text_guess,
            "encoding": self.encoding,
        }

    def render_text(self, color: bool = True) -> str:
        lines: List[str] = []
        best = self.best
        if best is None:
            lines.append(C.warn("No magic signature matched."))
            if self.text_guess:
                lines.append(f"{C.key('Text guess')} : {C.value(self.text_guess)}")
            return "\n".join(lines)
        lines.append(
            f"{C.key('Type')}       : {C.ok(best.signature.desc)} "
            f"({best.signature.ext})"
        )
        lines.append(f"{C.key('MIME')}       : {best.signature.mime}")
        lines.append(
            f"{C.key('Signature')}  : {best.signature.pattern.hex()} "
            f"@ offset {best.offset}"
        )
        if best.confidence < 0.5:
            lines.append(
                C.warn(
                    f"Note        : signature sits at offset {best.offset}, not at the "
                    f"file start — this is a padded / embedded container"
                )
            )
        if self.encoding:
            lines.append(f"{C.key('Encoding')}   : {self.encoding}")
        if len(self.matches) > 1:
            lines.append("")
            lines.append(C.title("Other candidates"))
            for match in self.matches[1:6]:
                lines.append(
                    f"  {C.dim(match.signature.pattern.hex())}  {match.signature.desc}"
                )
        return "\n".join(lines)


def sniff_text(data: bytes) -> tuple[Optional[str], Optional[str]]:
    """Cheap text/encoding sniffing.

    Returns:
        ``(kind, encoding)`` where *kind* is a coarse description such as
        ``"json"`` / ``"xml"`` / ``"html"`` / ``"shell script"`` /
        ``"plain text"`` and *encoding* is one of ``utf-8-sig``,
        ``utf-16-le``, ``utf-16-be``, ``utf-32-le``, ``utf-32-be``,
        ``utf-8`` or ``None``.
    """
    if not data:
        return ("empty", None)
    head = data[:4096]
    if head.startswith(b"\xef\xbb\xbf"):
        return ("text (BOM)", "utf-8-sig")
    if head.startswith(b"\xff\xfe\x00\x00"):
        return ("text (BOM)", "utf-32-le")
    if head.startswith(b"\x00\x00\xfe\xff"):
        return ("text (BOM)", "utf-32-be")
    if head.startswith(b"\xff\xfe"):
        return ("text (BOM)", "utf-16-le")
    if head.startswith(b"\xfe\xff"):
        return ("text (BOM)", "utf-16-be")
    printable = sum(1 for value in head if 0x20 <= value < 0x7F or value in (9, 10, 13))
    ratio = printable / len(head)
    if ratio < 0.85:
        return (None, None)
    try:
        text = head.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = head.decode("latin-1", "replace")
        encoding = "latin-1"
    stripped = text.lstrip()
    if stripped.startswith("#!"):
        interpreter = stripped[2:].split()[0] if len(stripped) > 2 else ""
        return (f"script ({interpreter})", encoding)
    if stripped[:1] in "{[":
        return ("json", encoding)
    if stripped.startswith("<?xml") or stripped.startswith("<"):
        low = stripped[:64].lower()
        if "<html" in low or "<!doctype html" in low:
            return ("html", encoding)
        if "<svg" in low:
            return ("svg", encoding)
        return ("xml", encoding)
    if stripped.startswith("---") and "\n" in stripped:
        return ("yaml front matter", encoding)
    return ("plain text", encoding)


def identify(data: bytes, extra: Optional[Iterable[Signature]] = None) -> IdentifyResult:
    """Identify *data* using the built-in (plus any *extra*) signatures."""
    table: List[Signature] = list(SIGNATURES)
    if extra:
        table = list(extra) + table
    matches: List[Match] = []
    for signature in table:
        found = signature.matches(data)
        if found is None:
            continue
        confidence = 1.0
        if signature.offset is None:
            # Floating signature: slightly less certain than an anchored one.
            confidence = 0.85 if found <= SEARCH_WINDOW else 0.6
        if len(signature.pattern) <= 2:
            confidence = min(confidence, 0.55)
        matches.append(Match(signature=signature, offset=found, confidence=confidence))
    if not matches:
        # Nothing anchored at the start: do one sweep inside the header window
        # so that padded / prefixed containers (firmware images, disk images,
        # "there is a PNG somewhere" blobs) still report a low-confidence hit.
        window = data[:SEARCH_WINDOW]
        found_at: Optional[int] = None
        found_sig: Optional[Signature] = None
        for signature in table:
            if len(signature.pattern) < 4:
                continue
            position = window.find(signature.pattern)
            if position >= 0 and (found_at is None or position < found_at):
                found_at, found_sig = position, signature
        if found_sig is not None and found_at is not None:
            matches.append(Match(signature=found_sig, offset=found_at, confidence=0.4))

    matches.sort(key=lambda match: (-match.confidence, match.offset, match.signature.desc))
    kind, encoding = sniff_text(data)
    return IdentifyResult(matches=matches, text_guess=kind, encoding=encoding)


def identify_stream(path: str, extra: Optional[Iterable[Signature]] = None) -> IdentifyResult:
    """Identify a file by path (only the first 64 KiB are read)."""
    from .reader import read_bytes

    data, _ = read_bytes(path, limit=65536)
    return identify(data, extra=extra)


def load_extra_signatures(text: str) -> List[Signature]:
    """Parse a user supplied signature file.

    One rule per line, ``offset|hexpattern|ext|mime|description``; ``offset``
    may be ``*`` for "search anywhere in the header window".  Blank lines and
    ``#`` comments are ignored.
    """
    out: List[Signature] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split("|")]
        if len(parts) < 3:
            raise ValueError(f"malformed signature line: {line!r}")
        offset_token, hex_token, ext = parts[0], parts[1], parts[2]
        mime = parts[3] if len(parts) > 3 else "application/octet-stream"
        desc = parts[4] if len(parts) > 4 else f"custom signature ({ext})"
        try:
            pattern = bytes.fromhex(hex_token.replace(" ", ""))
        except ValueError as exc:
            raise ValueError(f"invalid hex pattern in line: {line!r}") from exc
        if not pattern:
            raise ValueError(f"empty pattern in line: {line!r}")
        offset = None if offset_token in ("*", "", "-") else int(offset_token, 0)
        out.append(Signature(pattern=pattern, ext=ext, mime=mime, desc=desc, offset=offset))
    return out
