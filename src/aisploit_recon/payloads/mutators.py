"""Payload mutators.

These are *generic* text transforms (encodings, unicode tricks) used to test
whether a target's input filter normalises/decodes before inspecting content.
They are transport-level obfuscations, not model-specific safety bypasses:
the point is to measure filter coverage, e.g. "does the WAF decode base64
before scanning?".

Each mutator takes text and returns transformed text. They are pure and
side-effect free so they can be composed and property-tested.
"""

from __future__ import annotations

import base64
import codecs
from collections.abc import Callable

Mutator = Callable[[str], str]


def identity(text: str) -> str:
    return text


def base64_encode(text: str) -> str:
    """Tests whether the filter base64-decodes before scanning."""
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def rot13(text: str) -> str:
    return codecs.encode(text, "rot_13")


def leetspeak(text: str) -> str:
    # Both arguments to maketrans must be equal length; map a/e/i/o/s/t -> 4/3/1/0/$/7
    # for lower and upper case alike.
    table = str.maketrans("aeiostAEIOST", "4310$74310$7")
    return text.translate(table)


def unicode_homoglyph(text: str) -> str:
    """Substitute Latin letters with Cyrillic look-alikes to test normalisation."""
    homoglyphs = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441", "p": "\u0440"}
    return "".join(homoglyphs.get(ch, ch) for ch in text)


def zero_width_injection(text: str) -> str:
    """Insert zero-width spaces between characters to test tokenizer-level filters."""
    zwsp = "\u200b"
    return zwsp.join(text)


MUTATORS: dict[str, Mutator] = {
    "identity": identity,
    "base64": base64_encode,
    "rot13": rot13,
    "leetspeak": leetspeak,
    "homoglyph": unicode_homoglyph,
    "zero_width": zero_width_injection,
}


def apply_mutators(text: str, names: list[str]) -> str:
    """Apply mutators left-to-right. Unknown names raise (fail loud in config)."""
    out = text
    for name in names:
        try:
            out = MUTATORS[name](out)
        except KeyError as exc:
            raise ValueError(f"Unknown mutator: {name!r}. Known: {sorted(MUTATORS)}") from exc
    return out
