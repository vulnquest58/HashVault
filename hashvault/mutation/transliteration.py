"""Arabic normalization, Latin transliteration, and Arabizi variants."""

from __future__ import annotations

import re
from typing import Iterable

from hashvault.mutation.context import unique_terms


_DIACRITICS_RE = re.compile(r"[\u0610-\u061a\u064b-\u065f\u0670\u06d6-\u06ed\u0640]")
_ARABIC_RE = re.compile(r"[\u0600-\u06ff]")

_TRANSLITERATION = {
    "ا": "a",
    "أ": "a",
    "إ": "e",
    "آ": "a",
    "ب": "b",
    "ت": "t",
    "ث": "th",
    "ج": "j",
    "ح": "h",
    "خ": "kh",
    "د": "d",
    "ذ": "dh",
    "ر": "r",
    "ز": "z",
    "س": "s",
    "ش": "sh",
    "ص": "s",
    "ض": "d",
    "ط": "t",
    "ظ": "z",
    "ع": "a",
    "غ": "gh",
    "ف": "f",
    "ق": "q",
    "ك": "k",
    "ل": "l",
    "م": "m",
    "ن": "n",
    "ه": "h",
    "و": "w",
    "ي": "y",
    "ى": "a",
    "ة": "a",
    "ء": "",
    "ئ": "e",
    "ؤ": "o",
    "پ": "p",
    "چ": "ch",
    "ژ": "zh",
    "گ": "g",
}

_COMMON_NAMES = {
    "محمد": ["mohamed", "muhammad", "mhmd"],
    "احمد": ["ahmed", "ahmad", "hmd"],
    "أحمد": ["ahmed", "ahmad"],
    "محمود": ["mahmoud", "mahmud"],
    "علي": ["ali", "aly"],
    "حسن": ["hassan", "hasan"],
    "حسين": ["hussein", "husain"],
    "عمر": ["omar", "umer"],
    "خالد": ["khaled", "khalid"],
    "يوسف": ["youssef", "yusuf", "yousef"],
    "ابراهيم": ["ibrahim", "ebrahim"],
    "إبراهيم": ["ibrahim", "ebrahim"],
    "فاطمة": ["fatima", "fatma", "fatimah"],
    "سارة": ["sara", "sarah"],
    "نور": ["nour", "noor"],
    "ليلى": ["layla", "leila", "laila"],
    "مريم": ["mariam", "maryam"],
    "عبدالله": ["abdullah", "abdallah"],
}

_ARABIZI_MAP = {
    "2": "a",
    "3": "a",
    "5": "kh",
    "6": "t",
    "7": "h",
    "8": "gh",
    "9": "s",
}


def normalize_arabic(text: str) -> str:
    value = _DIACRITICS_RE.sub("", text or "")
    value = value.replace("أ", "ا").replace("إ", "ا").replace("آ", "ا")
    value = value.replace("ى", "ي").replace("ؤ", "و").replace("ئ", "ي")
    return value.strip()


def transliterate_arabic(text: str) -> str:
    normalized = normalize_arabic(text)
    return "".join(_TRANSLITERATION.get(char, char) for char in normalized)


def _decode_arabizi(text: str) -> str:
    return "".join(_ARABIZI_MAP.get(char, char) for char in text)


def _looks_arabizi(text: str) -> bool:
    if not re.search(r"[A-Za-z]", text):
        return False
    if re.search(r"(?:19|20)\d{2}", text):
        return False
    return bool(re.search(r"[2356789]", text))


def arabizi_variants(text: str) -> list[str]:
    value = (text or "").strip()
    if not value:
        return []
    variants = [value, _decode_arabizi(value), re.sub(r"[2356789]", "", value)]
    if "3" in value:
        variants.append(value.replace("3", "e"))
    if "9" in value:
        variants.append(value.replace("9", "s"))
    return unique_terms(variants)


def language_variants(term: str, language: str = "auto") -> list[str]:
    value = (term or "").strip()
    if not value:
        return []
    language = (language or "auto").lower()
    if language in {"off", "none", "disabled"}:
        return [value]
    variants: list[str] = [value]
    normalized = normalize_arabic(value)
    if normalized != value:
        variants.append(normalized)
    if _ARABIC_RE.search(value):
        variants.append(transliterate_arabic(value))
        variants.extend(_COMMON_NAMES.get(value, ()))
        variants.extend(_COMMON_NAMES.get(normalized, ()))
    if language in {"ar", "arabic", "arabizi", "auto"} and _looks_arabizi(value):
        variants.extend(arabizi_variants(value))
    return unique_terms(item for item in variants if item)


def expand_language_terms(terms: Iterable[str], language: str = "auto") -> list[str]:
    expanded: list[str] = []
    for term in terms:
        expanded.extend(language_variants(term, language))
    return unique_terms(expanded)
