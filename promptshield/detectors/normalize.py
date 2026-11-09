"""Canonicalise text so trivial obfuscation does not bypass the rules.

Handles: Unicode compatibility forms (fullwidth, math letters), zero-width and
bidi control characters, common Cyrillic/Greek homoglyphs, leetspeak, and
letter-spacing tricks like "i g n o r e".
"""
from __future__ import annotations

import re
import unicodedata

_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍‎‏⁠⁡⁢⁣⁤﻿"
             "‪‫‬‭‮⁦⁧⁨⁩­"),
    None,
)

_HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "ј": "j", "ѕ": "s", "ԁ": "d", "ɡ": "g", "ո": "n", "α": "a", "ε": "e", "ο": "o",
    "ρ": "p", "τ": "t", "ν": "v", "ι": "i", "κ": "k",
})

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})

# Runs of single letters separated by spaces/dots/dashes: "i g n o r e" -> "ignore"
_SPACED = re.compile(r"\b(?:[a-z][\s.\-_*]){3,}[a-z]\b")


def normalize(text: str, leet: bool = False) -> str:
    t = unicodedata.normalize("NFKC", text).translate(_INVISIBLE).translate(_HOMOGLYPHS)
    t = t.lower()
    t = _SPACED.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(0)), t)
    if leet:
        t = t.translate(_LEET)
    return re.sub(r"\s+", " ", t).strip()


def has_invisible_chars(text: str) -> bool:
    return any(ord(c) in _INVISIBLE for c in text)
