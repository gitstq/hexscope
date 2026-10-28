"""Output plumbing: JSON / Markdown / plain text emitters."""

from __future__ import annotations

import json
from typing import Any, List, Sequence

from .colors import C

__all__ = ["emit", "to_json", "markdown_table", "kv_table", "banner"]


def to_json(payload: Any, indent: int = 2) -> str:
    """Stable JSON dump (no ANSI, always UTF-8 friendly)."""
    return json.dumps(payload, indent=indent, ensure_ascii=False, sort_keys=False)


def markdown_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render a GitHub-flavoured Markdown table."""
    out: List[str] = []
    out.append("| " + " | ".join(str(h) for h in headers) + " |")
    out.append("| " + " | ".join("---" for _ in headers) + " |")
    for row in rows:
        out.append("| " + " | ".join("" if v is None else str(v) for v in row) + " |")
    return "\n".join(out)


def kv_table(pairs: Sequence[tuple[str, Any]], pad: int = 12) -> str:
    """Aligned ``key : value`` block."""
    width = max((len(str(k)) for k, _ in pairs), default=pad)
    width = max(width, pad)
    return "\n".join(f"{C.key(str(k).ljust(width))} : {v}" for k, v in pairs)


def emit(payload: Any, fmt: str = "text", renderer=None) -> str:
    """Emit *payload* in the requested format.

    Args:
        payload: the object to serialise (must be JSON-serialisable).
        fmt: ``text`` (uses *renderer*), ``json`` or ``md`` (a Markdown table
            built from ``payload`` when it is a ``list[dict]``).
        renderer: callable returning the plain-text rendering.
    """
    if fmt == "json":
        return to_json(payload)
    if fmt == "md":
        if isinstance(payload, dict) and "rows" in payload:
            return markdown_table(payload.get("headers", []), payload["rows"])
        if isinstance(payload, list) and payload and isinstance(payload[0], dict):
            headers = list(payload[0].keys())
            rows = [[row.get(h) for h in headers] for row in payload]
            return markdown_table(headers, rows)
        return "```json\n" + to_json(payload) + "\n```"
    if renderer is None:
        raise ValueError("text output requires a renderer")
    return renderer()


def banner(title: str, subtitle: str = "") -> str:
    """Small header used above every report."""
    line = C.title(title)
    if subtitle:
        line += C.dim(f"  — {subtitle}")
    return line
