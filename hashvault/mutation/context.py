"""Context profile loading for targeted password-audit guess generation."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

import yaml


_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)


@dataclass
class ContextProfile:
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    organization: Optional[str] = None
    project: Optional[str] = None
    domain: Optional[str] = None
    dates: list[str] = field(default_factory=list)
    locale: Optional[str] = None
    notes: Optional[str] = None
    keywords: list[str] = field(default_factory=list)
    source: Optional[str] = None

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "ContextProfile":
        if not data:
            return cls()
        dates = data.get("dates") or []
        keywords = data.get("keywords") or []
        if isinstance(dates, str):
            dates = [dates]
        if isinstance(keywords, str):
            keywords = [keywords]
        return cls(
            username=_clean(data.get("username") or data.get("user")),
            email=_clean(data.get("email")),
            display_name=_clean(data.get("display_name") or data.get("name")),
            organization=_clean(data.get("organization") or data.get("org")),
            project=_clean(data.get("project")),
            domain=_clean(data.get("domain")),
            dates=[str(item) for item in dates if str(item).strip()],
            locale=_clean(data.get("locale") or data.get("language")),
            notes=_clean(data.get("notes")),
            keywords=[str(item).strip() for item in keywords if str(item).strip()],
            source=_clean(data.get("source")),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> "ContextProfile":
        context_path = Path(path)
        text = context_path.read_text(encoding="utf-8")
        if context_path.suffix.lower() in {".yaml", ".yml"}:
            data = yaml.safe_load(text) or {}
        else:
            data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("Context file must contain a JSON/YAML object")
        profile = cls.from_mapping(data)
        profile.source = profile.source or str(context_path)
        return profile

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def is_empty(self) -> bool:
        return not any(
            (
                self.username,
                self.email,
                self.display_name,
                self.organization,
                self.project,
                self.domain,
                self.dates,
                self.notes,
                self.keywords,
            )
        )

    def seed_terms(self) -> list[str]:
        terms: list[str] = []
        for value in (
            self.username,
            self.display_name,
            self.organization,
            self.project,
            self.domain,
        ):
            if value:
                terms.append(value)
                terms.extend(_TOKEN_RE.findall(value))
        if self.email:
            terms.append(self.email)
            local, _, domain = self.email.partition("@")
            terms.append(local)
            terms.extend(_TOKEN_RE.findall(local))
            if domain:
                terms.append(domain)
                terms.extend(_TOKEN_RE.findall(domain.split(".")[0]))
        for date in self.dates:
            terms.append(date)
            terms.extend(re.findall(r"\d{4}", date))
        terms.extend(self.keywords)
        if self.notes:
            terms.extend(
                token
                for token in _TOKEN_RE.findall(self.notes)
                if 2 <= len(token) <= 40
            )
        return unique_terms(terms)

    def merged(self, **updates: Any) -> "ContextProfile":
        data = self.to_dict()
        for key, value in updates.items():
            if value is None:
                continue
            data[key] = value
        return ContextProfile.from_mapping(data)


def _clean(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def unique_terms(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        term = str(value).strip()
        if not term:
            continue
        key = term.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(term)
    return result
