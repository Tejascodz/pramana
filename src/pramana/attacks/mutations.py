"""Obfuscation mutators: the same attack, written so a text filter no longer sees it.

Input screens are usually regular expressions or keyword lists over the raw text.
A language model reads straight through invisible characters, look-alike letters
and split words; a regular expression does not. Each mutator here rewrites the
instruction words of a probe and leaves alone everything the verdict depends on:
quoted fragments ('TAN', 'GO-7741'), codes such as LANTERN-6650, the canary and
URLs. So a mutated probe is judged by exactly the same markers as the original.

Mutators are deterministic, so live runs replay offline and two audits of the
same system send the same text.

``normalize`` is the matching defence: run it on input before screening it.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable

ZWSP = "​"  # zero-width space
ZWNJ = "‌"  # zero-width non-joiner: legitimate inside Indic words, invisible
SOFT_HYPHEN = "­"

# Latin letters and the Cyrillic or Greek letters that look the same in most fonts.
HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "i": "і", "o": "о",
    "p": "р", "s": "ѕ", "x": "х", "y": "у", "j": "ј",
    "A": "А", "B": "В", "C": "С", "E": "Е", "H": "Н",
    "I": "І", "K": "Κ", "M": "М", "O": "О", "P": "Р",
    "T": "Т", "X": "Х", "Y": "Υ",
}  # fmt: skip
_FOLD = {v: k for k, v in HOMOGLYPHS.items()}
LEET = {"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"}

# Spans a mutator must never touch: quoted fragments, codes, braces, URLs, HTML.
PROTECTED = re.compile(
    r"'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`|\{[^}\n]*\}|https?://\S+|<[^>\n]*>"
    r"|\b[A-Z][A-Z0-9]*-\d+\b|\b[A-Z]{2,}\b"
)
LATIN_WORD = re.compile(r"[A-Za-z]{4,}")
INDIC_WORD = re.compile(r"[ऀ-෿]{3,}")


def _apply(text: str, word: re.Pattern[str], change: Callable[[str], str]) -> str:
    """Rewrite words matched by ``word`` outside protected spans."""
    out, last = [], 0
    for match in PROTECTED.finditer(text):
        out.append(word.sub(lambda m: change(m.group(0)), text[last : match.start()]))
        out.append(match.group(0))
        last = match.end()
    out.append(word.sub(lambda m: change(m.group(0)), text[last:]))
    return "".join(out)


def zero_width(text: str) -> str:
    """Hide a zero-width space in the middle of every word of four or more letters."""
    return _apply(text, LATIN_WORD, lambda w: w[: len(w) // 2] + ZWSP + w[len(w) // 2 :])


def homoglyph(text: str) -> str:
    """Swap Latin letters for Cyrillic and Greek look-alikes."""
    return _apply(text, LATIN_WORD, lambda w: "".join(HOMOGLYPHS.get(ch, ch) for ch in w))


def split(text: str) -> str:
    """Break words with soft hyphens (invisible unless the line wraps there)."""
    return _apply(
        text, LATIN_WORD, lambda w: SOFT_HYPHEN.join(w[i : i + 2] for i in range(0, len(w), 2))
    )


def spaced(text: str) -> str:
    """Spell instruction words out letter by letter: 'i g n o r e'."""
    return _apply(text, LATIN_WORD, lambda w: " ".join(w))


def leetspeak(text: str) -> str:
    """Replace letters with digits that look like them: 'ign0r3'."""
    return _apply(text, LATIN_WORD, lambda w: "".join(LEET.get(ch, ch) for ch in w))


def fullwidth(text: str) -> str:
    """Write letters in their full-width forms, common in East Asian text."""
    return _apply(text, LATIN_WORD, lambda w: "".join(chr(ord(ch) + 0xFEE0) for ch in w))


def indic_joiners(text: str) -> str:
    """Put zero-width non-joiners inside Devanagari, Kannada and Tamil words.

    The joiner is a legitimate character in Indic scripts and renders as nothing,
    so the text looks unchanged, but a filter matching the words no longer does.
    """

    def hide(word: str) -> str:
        # Insert before base letters only, never before a vowel sign or virama,
        # so every word still renders and reads normally.
        cuts = [i for i in range(1, len(word)) if not unicodedata.category(word[i]).startswith("M")]
        for i in sorted(cuts[::2], reverse=True):
            word = word[:i] + ZWNJ + word[i:]
        return word

    return _apply(text, INDIC_WORD, hide)


MUTATORS: dict[str, Callable[[str], str]] = {
    "zero_width": zero_width,
    "homoglyph": homoglyph,
    "split": split,
    "spaced": spaced,
    "leetspeak": leetspeak,
    "fullwidth": fullwidth,
    "indic_joiners": indic_joiners,
}

DESCRIPTIONS = {
    "zero_width": "invisible zero-width spaces inside words",
    "homoglyph": "Cyrillic and Greek look-alike letters",
    "split": "soft hyphens splitting words",
    "spaced": "words spelt out letter by letter",
    "leetspeak": "digits in place of letters",
    "fullwidth": "full-width letters",
    "indic_joiners": "zero-width joiners inside Indic-script words",
}


def mutate(text: str, name: str) -> str | None:
    """The mutated text, or None if the mutator changes nothing (no words to rewrite)."""
    changed = MUTATORS[name](text)
    return changed if changed != text else None


def normalize(text: str) -> str:
    """Undo these obfuscations before screening input. The matching defence.

    NFKC folds full-width and other compatibility forms, format characters
    (zero-width spaces and joiners, soft hyphens) are removed, and Cyrillic or
    Greek look-alikes are folded to Latin. Run screens on ``normalize(text)``.
    Letter-by-letter spacing and digit substitution need fuzzy matching on top.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return "".join(_FOLD.get(ch, ch) for ch in text)
