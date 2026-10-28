#!/usr/bin/env python3
"""Build and verify the deterministic layered-recipe benchmark corpus."""

from __future__ import annotations

import argparse
import base64
import binascii
import gzip
import json
import sys
import urllib.parse
import zlib
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from hashvault.analysis.analyzer import prepare_input

OUTPUT = PROJECT_ROOT / "data" / "corpus" / "layer_vectors.json"

MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
SHA256 = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
SHA512 = (
    "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb9"
    "80b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"
)
BCRYPT = "$2b$04$KKimJWG4bZewL437dNFCoOekyDTTKBjxS.0apAza9s/VtgPjgxbV6"
SHA512CRYPT = (
    "$6$hashvaultlayer$Rq2SseFlFC3381M8yFXAysIX55kxGlYY6px7eA8hnuiIaXoigbQ"
    "9mEN2KfrqER757.Fc7/G40a495FxjHu5fU0"
)

ENTRIES: list[dict[str, Any]] = [
    {
        "id": "layer-b64-md5",
        "raw_input": base64.b64encode(MD5.encode()).decode(),
        "expected_hash": MD5,
        "expected_operations": ["Base64"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Base64 wrapped MD5",
    },
    {
        "id": "layer-b64-sha256",
        "raw_input": base64.b64encode(SHA256.encode()).decode(),
        "expected_hash": SHA256,
        "expected_operations": ["Base64"],
        "expected_plaintext": "password",
        "expected_mode": 1400,
        "name": "Base64 wrapped SHA-256",
    },
    {
        "id": "layer-b64-sha512",
        "raw_input": base64.b64encode(SHA512.encode()).decode(),
        "expected_hash": SHA512,
        "expected_operations": ["Base64"],
        "expected_plaintext": "password",
        "expected_mode": 1700,
        "name": "Base64 wrapped SHA-512",
    },
    {
        "id": "layer-b32-md5",
        "raw_input": base64.b32encode(MD5.encode()).decode(),
        "expected_hash": MD5,
        "expected_operations": ["Base32"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Base32 wrapped MD5",
    },
    {
        "id": "layer-nested-b64-md5",
        "raw_input": base64.b64encode(
            base64.b64encode(MD5.encode())
        ).decode(),
        "expected_hash": MD5,
        "expected_operations": ["Base64", "Base64"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Double Base64 wrapped MD5",
    },
    {
        "id": "layer-url-b64-md5",
        "raw_input": urllib.parse.quote(
            base64.b64encode(MD5.encode()).decode(), safe=""
        ),
        "expected_hash": MD5,
        "expected_operations": ["URLDecode", "Base64"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "URL-encoded Base64 MD5",
    },
    {
        "id": "layer-gzip-b64-md5",
        "raw_input": base64.b64encode(gzip.compress(MD5.encode())).decode(),
        "expected_hash": MD5,
        "expected_operations": ["Base64", "Gzip"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Gzip inside Base64 MD5",
    },
    {
        "id": "layer-zlib-b64-md5",
        "raw_input": base64.b64encode(zlib.compress(MD5.encode())).decode(),
        "expected_hash": MD5,
        "expected_operations": ["Base64", "Zlib"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Zlib inside Base64 MD5",
    },
    {
        "id": "layer-json-md5",
        "raw_input": json.dumps({"password_hash": MD5}),
        "expected_hash": MD5,
        "expected_operations": ["ExtractEmbeddedHash"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "JSON embedded MD5",
    },
    {
        "id": "layer-json-sha256",
        "raw_input": json.dumps({"data": {"hash": SHA256}}),
        "expected_hash": SHA256,
        "expected_operations": ["ExtractEmbeddedHash"],
        "expected_plaintext": "password",
        "expected_mode": 1400,
        "name": "Nested JSON embedded SHA-256",
    },
    {
        "id": "layer-quoted-md5",
        "raw_input": f'"{MD5}"',
        "expected_hash": MD5,
        "expected_operations": ["ExtractEmbeddedHash"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "Quoted MD5",
    },
    {
        "id": "layer-csv-md5",
        "raw_input": f"user,{MD5}",
        "expected_hash": MD5,
        "expected_operations": ["ExtractEmbeddedHash"],
        "expected_plaintext": "password",
        "expected_mode": 0,
        "name": "CSV embedded MD5",
    },
    {
        "id": "layer-hex-bcrypt",
        "raw_input": binascii.hexlify(BCRYPT.encode()).decode(),
        "expected_hash": BCRYPT,
        "expected_operations": ["Hex"],
        "expected_plaintext": "Layer2026!",
        "expected_mode": 3200,
        "name": "Hex wrapped bcrypt",
    },
    {
        "id": "layer-hex-sha512crypt",
        "raw_input": binascii.hexlify(SHA512CRYPT.encode()).decode(),
        "expected_hash": SHA512CRYPT,
        "expected_operations": ["Hex"],
        "expected_plaintext": "Layer2026!",
        "expected_mode": 1800,
        "name": "Hex wrapped sha512crypt",
    },
    {
        "id": "layer-gzip-b64-sha256",
        "raw_input": base64.b64encode(gzip.compress(SHA256.encode())).decode(),
        "expected_hash": SHA256,
        "expected_operations": ["Base64", "Gzip"],
        "expected_plaintext": "password",
        "expected_mode": 1400,
        "name": "Gzip inside Base64 SHA-256",
    },
    {
        "id": "layer-zlib-b64-sha512",
        "raw_input": base64.b64encode(zlib.compress(SHA512.encode())).decode(),
        "expected_hash": SHA512,
        "expected_operations": ["Base64", "Zlib"],
        "expected_plaintext": "password",
        "expected_mode": 1700,
        "name": "Zlib inside Base64 SHA-512",
    },
    {
        "id": "layer-url-b64-sha256",
        "raw_input": urllib.parse.quote(
            base64.b64encode(SHA256.encode()).decode(), safe=""
        ),
        "expected_hash": SHA256,
        "expected_operations": ["URLDecode", "Base64"],
        "expected_plaintext": "password",
        "expected_mode": 1400,
        "name": "URL encoded Base64 SHA-256",
    },
    {
        "id": "layer-gzip-b64-sha512crypt",
        "raw_input": base64.b64encode(gzip.compress(SHA512CRYPT.encode())).decode(),
        "expected_hash": SHA512CRYPT,
        "expected_operations": ["Base64", "Gzip"],
        "expected_plaintext": "Layer2026!",
        "expected_mode": 1800,
        "name": "Gzip inside Base64 sha512crypt",
    },
]


def build_document() -> dict[str, Any]:
    entries = []
    for entry in ENTRIES:
        item = {
            **entry,
            "source": "hashvault-layer-corpus",
            "notes": "Deterministic transform vector verified by prepare_input.",
        }
        handoff = prepare_input(
            item["raw_input"],
            max_layers=12,
            beam_width=8,
            max_seconds=10.0,
        )
        actual_ops = [layer.operation for layer in handoff.trace.layers]
        if actual_ops != item["expected_operations"]:
            raise SystemExit(
                f"{item['id']}: expected {item['expected_operations']}, got {actual_ops}"
            )
        if handoff.primary != item["expected_hash"]:
            raise SystemExit(
                f"{item['id']}: expected hash {item['expected_hash']!r}, "
                f"got {handoff.primary!r}"
            )
        if not handoff.trace.terminal:
            raise SystemExit(f"{item['id']}: terminal hash not detected")
        entries.append(item)
    return {
        "version": 1,
        "description": "Deterministic wrapped-hash vectors for recipe benchmarking.",
        "counts": {
            "total": len(entries),
            "with_plaintext": sum(bool(item.get("expected_plaintext")) for item in entries),
            "with_mode": sum(item.get("expected_mode") is not None for item in entries),
            "operations": sorted(
                {op for item in entries for op in item["expected_operations"]}
            ),
        },
        "entries": entries,
    }


def serialized(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify that the checked-in corpus matches the generator.",
    )
    args = parser.parse_args()
    content = serialized(build_document())
    if args.check:
        if not OUTPUT.exists():
            print(f"Missing layer corpus: {OUTPUT}")
            return 1
        if OUTPUT.read_text(encoding="utf-8") != content:
            print(f"Layer corpus is stale: {OUTPUT}")
            return 1
        print("Layer corpus is up to date.")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(content, encoding="utf-8")
    print(f"Wrote {OUTPUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
