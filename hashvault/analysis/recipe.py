"""
Recipe engine: recursively "peel" encoding layers off the raw input until the
inner hash becomes stable, recording a transparent trace of every layer.

Mirrors CyberChef's Recipe concept:
  - Each Layer corresponds to one Operation applied successfully.
  - The engine stops when:
      a) No operation scores above threshold (nothing to peel), OR
      b) HashDetector fires (input is already a bare hash), OR
      c) max_depth is reached, OR
      d) A cycle is detected (seen-set guard).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from hashvault.analysis.magic import detect
from hashvault.analysis.operations import _hash_likeness, _looks_plain

import re as _re

# Lengths for common hash algorithms (hex-encoded)
_HEX_HASH_LENGTHS = {32, 40, 48, 56, 64, 96, 128}  # MD5→SHA-512
_HEX_RE = _re.compile(r'^[0-9a-fA-F]+$')


def _is_bare_hash_strict(text: str) -> bool:
    """Pre-loop fast-path: only matches input that is UNAMBIGUOUSLY a bare hash.

    Uses known hash hex-lengths (32=MD5, 40=SHA1, 48=SHA-384/Tiger, 56=SHA-224,
    64=SHA-256/Whirlpool, 96=SHA-384, 128=SHA-512) plus structured formats.
    Short hex strings (e.g. hex-encoded plaintext like 'password' = 16 chars)
    are intentionally NOT matched so the recipe can still decode them.
    """
    s = text.strip()
    if not s:
        return False
    # Pure hex at a known hash length only
    if len(s) in _HEX_HASH_LENGTHS and _HEX_RE.match(s):
        return True
    # Any $identifier$ format: bcrypt, sha512crypt, 7z, zip, krb5, WPA, argon2, etc.
    if s.startswith("$") and s.count("$") >= 2:
        return True
    # PBKDF2 / Django colon format: "sha256:260000:salt:hash"
    if s.startswith(("sha256:", "sha512:", "sha1:", "pbkdf2_sha")):
        return True
    # NTLMv2 / NetNTLM double-colon separator
    if "::" in s:
        return True
    # Generic colon-separated (user:LM:NT:...) with >=3 colons
    if s.count(":") >= 3:
        return True
    return False


def _is_bare_hash(text: str) -> bool:
    """Post-layer guard: stops cipher ops being applied to decoded hex outputs.

    Broader than _is_bare_hash_strict — any pure-hex string >= 16 chars is
    treated as a potential hash to prevent ROT47/ROT13/Atbash being applied.
    """
    s = text.strip()
    if not s:
        return False
    # Pure hex of ANY reasonable length (>=16 chars)
    if len(s) >= 16 and _HEX_RE.match(s):
        return True
    # Any $identifier$ format
    if s.startswith("$") and s.count("$") >= 2:
        return True
    # PBKDF2 / Django colon format
    if s.startswith(("sha256:", "sha512:", "sha1:", "pbkdf2_sha")):
        return True
    # NTLMv2 double-colon separator
    if "::" in s:
        return True
    # Generic colon-separated
    if s.count(":") >= 3:
        return True
    return False



@dataclass
class Layer:
    """One decoded layer in the analysis trace."""

    operation: str
    input_text: str
    output_text: str
    confidence: float
    depth: int
    category: str = "Other"
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def changed(self) -> bool:
        return self.input_text != self.output_text


@dataclass
class AnalysisTrace:
    """Full unwrapping result: the final text plus the applied layers."""

    raw_input: str
    finalized_input: str
    layers: List[Layer]
    terminal: bool = False
    score: float = 0.0
    kind: str = "text"
    label: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    @property
    def layers_applied(self) -> int:
        return len(self.layers)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "raw_input": self.raw_input,
            "finalized_input": self.finalized_input,
            "chain": self.describe(),
            "layers_applied": self.layers_applied,
            "terminal": self.terminal,
            "score": round(self.score, 4),
            "kind": self.kind,
            "label": self.label,
            "metadata": self.metadata,
            "warnings": list(self.warnings),
            "layers": [
                {
                    "operation": layer.operation,
                    "category": layer.category,
                    "depth": layer.depth,
                    "input": layer.input_text,
                    "output": layer.output_text,
                    "confidence": round(layer.confidence, 3),
                    "label": layer.label,
                    "metadata": layer.metadata,
                }
                for layer in self.layers
            ],
        }

    def describe(self) -> str:
        """Compact human-readable chain, e.g. 'Base64 → Hex → (hash)'."""
        chain = " → ".join(layer.operation for layer in self.layers)
        return chain or "(no unwrapping needed)"

    def describe_verbose(self) -> str:
        """Multi-line verbose description of each layer."""
        if not self.layers:
            return "No layers detected — input appears to be a bare hash."
        lines = []
        for i, layer in enumerate(self.layers, 1):
            inp = layer.input_text[:60] + ("…" if len(layer.input_text) > 60 else "")
            out = layer.output_text[:60] + ("…" if len(layer.output_text) > 60 else "")
            lines.append(
                f"  Layer {i}: [{layer.category}] {layer.operation} "
                f"(conf={layer.confidence:.0%})\n"
                f"    IN : {inp!r}\n"
                f"    OUT: {out!r}"
            )
        return "\n".join(lines)


_STOP_OPS = {"HashDetector"}
_EXTRACT_OPS = {
    "ExtractIP", "ExtractEmails", "ExtractURLs", "ExtractMAC",
    "ExtractBase64", "ExtractJWTPayload",
}


def unpack_layers(
    text: str,
    max_depth: int = 10,
    require_progress: bool = True,
    *,
    min_score: float = 0.05,
    allow_extractors: bool = False,
) -> AnalysisTrace:
    """
    Repeatedly apply the best-scoring operation until no further meaningful
    progress can be made (or ``max_depth`` is reached), guarding against
    infinite loops and oscillation.

    Selection rule:
      1. Among operations that decode successfully AND actually change the text,
         pick the highest-confidence one.
      2. Tie-break toward the more "hash-like" output.
      3. HashDetector fires → stop immediately (input is already a hash).
      4. Extractor ops are skipped unless ``allow_extractors=True``.

    Parameters
    ----------
    text:
        Raw user input (possibly encoded).
    max_depth:
        Maximum number of encoding layers to peel.
    require_progress:
        If True, stop when the best candidate produces no change.
    min_score:
        Minimum confidence score for an operation to be considered.
    allow_extractors:
        If True, allow Extractor category ops (IP/email/URL extraction).
        Default False — extractors are used in the CLI `analyze` command only.
    """
    raw = (text or "").strip()
    current = raw
    seen = {current}
    layers: List[Layer] = []

    # Fast path: if the raw input is UNAMBIGUOUSLY a bare hash,
    # skip the entire loop — no unwrapping is needed or appropriate.
    if _is_bare_hash_strict(raw):
        return AnalysisTrace(raw_input=raw, finalized_input=raw, layers=[])

    for depth in range(1, max_depth + 1):
        best_op = None
        best_out: Optional[str] = None
        best_score = -1.0
        best_gain = float("-inf")
        best_category = "Other"

        for candidate in detect(current, min_score=min_score):
            op = candidate.operation

            # Skip extractor ops unless explicitly enabled
            if op.category == "Extractors" and not allow_extractors:
                continue

            # HashDetector — stop peeling only if current is UNAMBIGUOUSLY
            # a bare hash (known length, $format$, ::, etc.).
            # Without this guard, HashDetector fires on any long hex string
            # (e.g. 80-char hex-encoded SHA1) and prevents Hex decode.
            if op.name in _STOP_OPS and _is_bare_hash_strict(current):
                return AnalysisTrace(
                    raw_input=raw,
                    finalized_input=current,
                    layers=layers,
                )

            try:
                out = op.apply(current)
            except Exception:
                continue
            if out is None or out == current:
                continue
            # Only strip whitespace from printable-text outputs.
            # Binary payloads (gzip, bzip2, lzma passed as latin-1 strings)
            # must NOT be stripped — their headers/trailers contain meaningful
            # bytes (e.g. 0x0a = \n in CRC32) that .strip() would destroy.
            if _looks_plain(out):
                out = out.strip()
            if not out:
                continue

            score = candidate.score
            gain = score * 10 + _hash_likeness(out)
            if gain > best_gain:
                best_gain = gain
                best_score = score
                best_op = op
                best_out = out
                best_category = op.category

        if best_op is None or best_out is None:
            break
        if best_out in seen:
            break
        if require_progress and best_out == current.strip():
            break


        layers.append(
            Layer(
                operation=best_op.name,
                input_text=current,
                output_text=best_out,
                confidence=best_score,
                depth=depth,
                category=best_category,
            )
        )
        seen.add(best_out)
        current = best_out

        # Early stop: if the unwrapped output already looks like a bare hash,
        # don't continue peeling (avoids e.g. ROT47 being applied to hex hashes)
        if _is_bare_hash(current):
            break

    return AnalysisTrace(
        raw_input=raw,
        finalized_input=current,
        layers=layers,
    )
