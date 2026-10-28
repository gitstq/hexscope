"""Terminal colour helpers.

Design goals (self-imposed, no third-party dependency):

* honour ``NO_COLOR`` / ``FORCE_COLOR`` environment variables;
* disable colour when stdout is not a TTY (pipes, CI logs);
* expose a tiny ``C`` singleton so every renderer can stay dumb.

The module never raises: colour is strictly cosmetic.
"""

from __future__ import annotations

import os
import sys

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

FG_BLACK = "\033[30m"
FG_RED = "\033[31m"
FG_GREEN = "\033[32m"
FG_YELLOW = "\033[33m"
FG_BLUE = "\033[34m"
FG_MAGENTA = "\033[35m"
FG_CYAN = "\033[36m"
FG_WHITE = "\033[37m"
FG_GREY = "\033[90m"
FG_BRIGHT_RED = "\033[91m"
FG_BRIGHT_GREEN = "\033[92m"
FG_BRIGHT_YELLOW = "\033[93m"
FG_BRIGHT_BLUE = "\033[94m"
FG_BRIGHT_CYAN = "\033[96m"
FG_BRIGHT_WHITE = "\033[97m"


def _env_flag(name: str) -> bool | None:
    """Return ``True``/``False`` for a *set* env flag, ``None`` when unset."""
    raw = os.environ.get(name)
    if raw is None:
        return None
    raw = raw.strip()
    if raw == "":
        # ``NO_COLOR`` with an empty value is treated as "not set" (per spec).
        return None
    return raw not in ("0", "false", "False", "no")


class Palette:
    """A colour palette that can be switched off globally at runtime."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    # -- control ---------------------------------------------------------
    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    def wrap(self, text: str, *codes: str) -> str:
        """Wrap *text* with ANSI codes (no-op when colour is disabled)."""
        if not self.enabled or not codes:
            return text
        return "".join(codes) + text + RESET

    # -- semantic helpers ------------------------------------------------
    def offset(self, text: str) -> str:
        return self.wrap(text, FG_BLUE)

    def hex_zero(self, text: str) -> str:
        return self.wrap(text, FG_GREY)

    def hex_printable(self, text: str) -> str:
        return self.wrap(text, FG_GREEN)

    def hex_high(self, text: str) -> str:
        return self.wrap(text, FG_YELLOW)

    def hex_control(self, text: str) -> str:
        return self.wrap(text, FG_RED)

    def ascii_bar(self, text: str) -> str:
        return self.wrap(text, FG_CYAN)

    def key(self, text: str) -> str:
        return self.wrap(text, FG_BRIGHT_CYAN, BOLD)

    def value(self, text: str) -> str:
        return self.wrap(text, FG_BRIGHT_WHITE)

    def ok(self, text: str) -> str:
        return self.wrap(text, FG_BRIGHT_GREEN)

    def warn(self, text: str) -> str:
        return self.wrap(text, FG_BRIGHT_YELLOW)

    def error(self, text: str) -> str:
        return self.wrap(text, FG_BRIGHT_RED)

    def dim(self, text: str) -> str:
        return self.wrap(text, DIM)

    def bold(self, text: str) -> str:
        return self.wrap(text, BOLD)

    def title(self, text: str) -> str:
        return self.wrap(text, BOLD, FG_BRIGHT_BLUE)


def detect_color(override: bool | None = None) -> bool:
    """Decide whether ANSI colour should be emitted.

    Priority: explicit *override* > ``NO_COLOR`` > ``FORCE_COLOR`` > TTY check.
    """
    if override is not None:
        return override
    no_color = _env_flag("NO_COLOR")
    if no_color:
        return False
    force = _env_flag("FORCE_COLOR")
    if force is not None:
        return force
    try:
        return bool(sys.stdout.isatty())
    except Exception:  # pragma: no cover - defensive
        return False


#: Global palette used by all renderers.
C = Palette(detect_color())


def set_color(enabled: bool | None) -> None:
    """Enable/disable colour globally (``None`` re-runs auto detection)."""
    C.enabled = detect_color() if enabled is None else enabled
