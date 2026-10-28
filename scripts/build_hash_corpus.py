#!/usr/bin/env python3
"""Build the static Hashcat example corpus from patterns.meta.json."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_META = PROJECT_ROOT / "data" / "patterns" / "patterns.meta.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "corpus" / "hashcat_examples.json"
REFERENCE = "https://hashcat.net/wiki/doku.php?id=example_hashes"


def _as_bool(value: Any) -> bool:
    return str(value).strip().lower() in {"yes", "true", "1"}


def _clean(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.strip()


def build_entry(mode: int, meta: dict[str, Any]) -> dict[str, Any]:
    example_format = _clean(meta.get("Example.Hash.Format")) or "unknown"
    raw_input = _clean(meta.get("Example.Hash"))
    expected_plaintext = _clean(meta.get("Example.Pass"))
    binary_only = example_format == "hex-encoded (binary file only)"
    truncated = "[Truncated" in raw_input
    no_example = example_format == "N/A" or raw_input in {"", "N/A"}

    unusable: list[str] = []
    if no_example:
        unusable.append("no usable example")
    if binary_only:
        unusable.append("binary file only")
    if truncated:
        unusable.append("truncated example")
    usable_identification = not unusable
    if expected_plaintext in {"", "N/A"}:
        expected_plaintext = ""

    return {
        "id": f"hashcat-{mode}",
        "source": "hashcat",
        "mode": mode,
        "name": _clean(meta.get("Name")),
        "category": _clean(meta.get("Category")),
        "hashcat_category": _clean(meta.get("Category")),
        "raw_input": raw_input,
        "expected_plaintext": expected_plaintext or None,
        "example_format": example_format,
        "slow_hash": _as_bool(meta.get("Slow.Hash")),
        "is_binary": binary_only,
        "truncated": truncated,
        "usable_for_identification": usable_identification,
        "usable_for_cracking": usable_identification and bool(expected_plaintext),
        "unusable_reason": ", ".join(unusable) or None,
        "reference": REFERENCE,
        "notes": f"Hashcat {mode} example from patterns.meta.json.",
    }


def build_document(meta_path: Path = DEFAULT_META) -> dict[str, Any]:
    raw_bytes = meta_path.read_bytes()
    metadata = json.loads(raw_bytes.decode("utf-8"))
    entries = [
        build_entry(int(mode), value)
        for mode, value in sorted(metadata.items(), key=lambda item: int(item[0]))
    ]

    ids = [entry["id"] for entry in entries]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate corpus entry ids")

    return {
        "schema_version": 1,
        "source": "hashcat",
        "description": (
            "Plaintext Hashcat example hashes and expected passwords generated "
            "from the local patterns.meta.json catalog."
        ),
        "generated_from": str(meta_path.relative_to(PROJECT_ROOT)).replace("\\", "/"),
        "source_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "counts": {
            "total": len(entries),
            "with_plaintext": sum(1 for entry in entries if entry["expected_plaintext"]),
            "usable_for_identification": sum(
                1 for entry in entries if entry["usable_for_identification"]
            ),
            "usable_for_cracking": sum(
                1 for entry in entries if entry["usable_for_cracking"]
            ),
            "binary_only": sum(1 for entry in entries if entry["is_binary"]),
            "truncated": sum(1 for entry in entries if entry["truncated"]),
            "no_example": sum(
                1
                for entry in entries
                if entry["unusable_reason"] and "no usable example" in entry["unusable_reason"]
            ),
        },
        "entries": entries,
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--meta", type=Path, default=DEFAULT_META)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the existing corpus is stale.",
    )
    args = parser.parse_args()

    document = build_document(args.meta)
    content = render(document)

    if args.check:
        if not args.output.exists():
            print(f"missing corpus: {args.output}", file=sys.stderr)
            return 1
        if args.output.read_text(encoding="utf-8") != content:
            print(f"stale corpus: {args.output}", file=sys.stderr)
            return 1
        print(f"up to date: {args.output}")
        return 0

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(content, encoding="utf-8")
    counts = document["counts"]
    print(
        f"wrote {args.output} ({counts['total']} modes, "
        f"{counts['usable_for_identification']} identification-ready, "
        f"{counts['usable_for_cracking']} crack-ready)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
