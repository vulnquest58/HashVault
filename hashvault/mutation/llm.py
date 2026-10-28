"""Optional local Ollama seed suggestions for authorized audits."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional, Sequence

from hashvault.mutation.context import ContextProfile, unique_terms
from hashvault.mutation.seeds import Seed


class LLMError(RuntimeError):
    pass


@dataclass
class LLMSettings:
    enabled: bool = False
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.2"
    timeout_seconds: float = 20.0
    max_candidates: int = 25
    allow_remote_endpoint: bool = False

    @classmethod
    def from_config(cls, config: Any) -> "LLMSettings":
        raw = getattr(config, "llm", None)
        if raw is None:
            return cls()
        return cls(
            enabled=bool(getattr(raw, "enabled", False)),
            base_url=str(getattr(raw, "base_url", cls.base_url)),
            model=str(getattr(raw, "model", cls.model)),
            timeout_seconds=float(getattr(raw, "timeout_seconds", 20.0)),
            max_candidates=int(getattr(raw, "max_candidates", 25)),
            allow_remote_endpoint=bool(
                getattr(raw, "allow_remote_endpoint", False)
            ),
        )


_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _is_loopback(url: str) -> bool:
    """Return True when ``url`` points at this host."""
    host = urllib.parse.urlparse(url).hostname or ""
    return host.lower() in _LOOPBACK_HOSTS


def _prompt(context: ContextProfile, seeds: Sequence[Seed], count: int) -> str:
    context_data = {
        key: value
        for key, value in context.to_dict().items()
        if value not in (None, "", [], {})
    }
    seed_terms = [seed.term for seed in seeds[:30]]
    return (
        "You generate candidate passwords for an authorized password audit. "
        "Use only the supplied context. Return JSON with a single key "
        '"candidates" containing a short array of candidate strings. '
        "Do not include explanations or markdown.\n"
        f"Context: {json.dumps(context_data, ensure_ascii=False)}\n"
        f"Known seed terms: {json.dumps(seed_terms, ensure_ascii=False)}\n"
        f"Maximum candidates: {count}"
    )


def _extract_candidates(payload: Any, limit: int) -> list[str]:
    if isinstance(payload, dict):
        values = payload.get("candidates") or payload.get("passwords") or []
    elif isinstance(payload, list):
        values = payload
    else:
        values = []
    candidates = []
    for value in values if isinstance(values, list) else []:
        term = str(value).strip()
        if not term or len(term) > 96 or re.search(r"[\x00-\x1f]", term):
            continue
        candidates.append(term)
    return unique_terms(candidates)[:limit]


class OllamaSeeder:
    def __init__(self, settings: LLMSettings):
        self.settings = settings

    def _request(self, prompt: str) -> dict[str, Any]:
        url = self.settings.base_url.rstrip("/") + "/api/generate"
        if not self.settings.allow_remote_endpoint and not _is_loopback(url):
            # Refuse to send audit context off-host.  The README promises that
            # only local endpoints are contacted; a config-supplied base_url
            # previously bypassed that promise silently.
            raise LLMError(
                "Refusing to contact a non-loopback LLM endpoint "
                f"({url}). Set llm.allow_remote_endpoint=true to allow it."
            )
        body = json.dumps(
            {
                "model": self.settings.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.4},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=self.settings.timeout_seconds
            ) as response:
                raw = response.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise LLMError(f"Local LLM request failed: {exc}") from exc
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise LLMError("Local LLM returned invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise LLMError("Local LLM response must be a JSON object")
        return parsed

    def suggest(
        self,
        context: ContextProfile,
        seeds: Sequence[Seed],
        count: Optional[int] = None,
    ) -> list[str]:
        if not self.settings.enabled:
            raise LLMError("Local LLM support is disabled in configuration")
        limit = count or self.settings.max_candidates
        if limit <= 0:
            return []
        response = self._request(_prompt(context, seeds, limit))
        inner = response.get("response", response)
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except json.JSONDecodeError as exc:
                raise LLMError("Local LLM response content was not JSON") from exc
        candidates = _extract_candidates(inner, limit)
        if not candidates:
            raise LLMError("Local LLM returned no usable candidates")
        return candidates
