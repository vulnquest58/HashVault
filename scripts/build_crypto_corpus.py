#!/usr/bin/env python3
"""Build the curated public crypto known-answer corpus.

Vectors are taken from pinned upstream test files and verified locally with
Python's hashlib, bcrypt, or passlib before they are written to the corpus.
"""

from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import importlib
import inspect
import json
import re
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "corpus" / "crypto_vectors.json"
META_PATH = PROJECT_ROOT / "data" / "patterns" / "patterns.meta.json"
USER_AGENT = "HashVault-crypto-corpus/1.0"


@dataclass(frozen=True)
class Source:
    key: str
    repo: str
    commit: str
    license: str
    files: tuple[str, ...]


SOURCES = {
    "django": Source(
        "django",
        "django/django",
        "36920bb4766679f5b32445797dcc5d32b8ff5ad2",
        "BSD-3-Clause",
        ("tests/auth_tests/test_hashers.py",),
    ),
    "bcrypt": Source(
        "bcrypt",
        "pyca/bcrypt",
        "35b3dbec3a5a6102889772c2c46c8ee493564572",
        "Apache-2.0",
        ("tests/test_bcrypt.py",),
    ),
    "php": Source(
        "php",
        "php/php-src",
        "49b2bc4532ec00859256707ac3771657d2889808",
        "PHP-3.01",
        (
            "ext/standard/tests/strings/crypt.phpt",
            "ext/standard/tests/password/password_verify.phpt",
        ),
    ),
    "openssl": Source(
        "openssl",
        "openssl/openssl",
        "a752594ed84476fbb516b0f43e15de513dcd4a14",
        "Apache-2.0",
        (
            "test/recipes/30-test_evp_data/evpkdf_pbkdf2.txt",
            "test/recipes/30-test_evp_data/evpkdf_scrypt.txt",
        ),
    ),
    "go": Source(
        "go",
        "golang/crypto",
        "9f2b28d4331a80cb1ffd8fd7f1cf6207b696281b",
        "BSD-3-Clause",
        ("bcrypt/bcrypt_test.go",),
    ),
}

PASSLIB_CLASSES: dict[str, tuple[str, int]] = {
    "apr_md5_crypt_test": ("apr_md5_crypt", 1600),
    "_bsdi_crypt_test": ("bsdi_crypt", 12400),
    "_des_crypt_test": ("des_crypt", 1500),
    "hex_md4_test": ("hex_md4", 900),
    "hex_md5_test": ("hex_md5", 0),
    "hex_sha1_test": ("hex_sha1", 100),
    "hex_sha256_test": ("hex_sha256", 1400),
    "hex_sha512_test": ("hex_sha512", 1700),
    "ldap_salted_sha1_test": ("ldap_salted_sha1", 111),
    "ldap_salted_sha256_test": ("ldap_salted_sha256", 1411),
    "ldap_salted_sha512_test": ("ldap_salted_sha512", 1711),
    "lmhash_test": ("lmhash", 3000),
    "_md5_crypt_test": ("md5_crypt", 500),
    "mssql2000_test": ("mssql2000", 131),
    "mssql2005_test": ("mssql2005", 132),
    "mysql323_test": ("mysql323", 200),
    "mysql41_test": ("mysql41", 300),
    "nthash_test": ("nthash", 1000),
    "phpass_test": ("phpass", 400),
    "_sha1_crypt_test": ("sha1_crypt", 15100),
    "_sha256_crypt_test": ("sha256_crypt", 7400),
    "_sha512_crypt_test": ("sha512_crypt", 1800),
    "atlassian_pbkdf2_sha1_test": ("atlassian_pbkdf2_sha1", 12001),
    "pbkdf2_sha1_test": ("pbkdf2_sha1", 20400),
    "pbkdf2_sha256_test": ("pbkdf2_sha256", 20300),
    "pbkdf2_sha512_test": ("pbkdf2_sha512", 20200),
}
MAX_PASSLIB_VECTORS = 6


def _meta() -> dict[str, Any]:
    return json.loads(META_PATH.read_text(encoding="utf-8"))


def _mode_info(meta: dict[str, Any], mode: int) -> tuple[str, str, bool]:
    item = meta.get(str(mode), {})
    name = str(item.get("Name") or f"Hashcat mode {mode}")
    category = str(item.get("Category") or "crypto")
    slow = str(item.get("Slow.Hash", "")).strip().lower() in {"yes", "true", "1"}
    return name, category, slow


def _raw_url(source: Source, path: str) -> str:
    return f"https://raw.githubusercontent.com/{source.repo}/{source.commit}/{path}"


def _blob_url(source: Source, path: str, line: int | None = None) -> str:
    url = f"https://github.com/{source.repo}/blob/{source.commit}/{path}"
    return f"{url}#L{line}" if line else url


def _fetch(url: str) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=60) as response:
        return response.read()


def _decode(data: bytes) -> str:
    return data.decode("utf-8")


def _make_entry(
    *,
    source_key: str,
    source: Source,
    path: str,
    line: int | None,
    mode: int,
    plaintext: str,
    raw_input: str,
    meta: dict[str, Any],
    verification: str,
    notes: str,
) -> dict[str, Any]:
    name, category, slow = _mode_info(meta, mode)
    identity = hashlib.sha256(
        f"{source_key}\0{mode}\0{raw_input}\0{plaintext}".encode("utf-8")
    ).hexdigest()[:12]
    return {
        "id": f"crypto-{source_key}-{mode}-{identity}",
        "source": "crypto",
        "mode": mode,
        "name": name,
        "raw_input": raw_input,
        "expected_plaintext": plaintext,
        "category": category,
        "example_format": "plain",
        "slow_hash": slow,
        "is_binary": False,
        "truncated": False,
        "usable_for_identification": True,
        "usable_for_cracking": True,
        "unusable_reason": None,
        "reference": _blob_url(source, path, line),
        "notes": notes,
        "upstream_repo": source.repo,
        "upstream_path": path,
        "upstream_commit": source.commit,
        "upstream_url": _blob_url(source, path, line),
        "license": source.license,
        "verified": True,
        "verification": verification,
    }


def _verify_django_pbkdf2(raw_input: str, plaintext: str) -> None:
    algorithm, iterations, salt, expected = raw_input.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        plaintext.encode("utf-8"),
        salt.encode("utf-8"),
        int(iterations),
    )
    actual = base64.b64encode(digest).decode("ascii")
    if actual != expected:
        raise ValueError("Django PBKDF2 known-answer verification failed")


def _django_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    source = SOURCES["django"]
    path = source.files[0]
    text = _decode(_fetch(_raw_url(source, path)))
    compact = re.sub(r'["\s]', "", text)
    vectors = (
        (
            88,
            "pbkdf2_sha256$1800000$seasalt$sXv9FzN4gEo6/P8G5H1jvir9BIb5e5EkXoVGyjOniNE=",
            "lètmein",
        ),
        (
            282,
            "pbkdf2_sha256$1800000$seasalt2$swjWuQn/bYIeQWF1JQRMdMdckgYo6ZXtwyjAMt8Nxdg=",
            "lètmein",
        ),
    )
    entries: list[dict[str, Any]] = []
    for line, raw_input, plaintext in vectors:
        if raw_input not in compact:
            raise ValueError(f"Django vector missing from pinned source: {raw_input}")
        _verify_django_pbkdf2(raw_input, plaintext)
        entries.append(
            _make_entry(
                source_key="django",
                source=source,
                path=path,
                line=line,
                mode=10000,
                plaintext=plaintext,
                raw_input=raw_input,
                meta=meta,
                verification="python:hashlib.pbkdf2_hmac",
                notes="Django PBKDF2-SHA256 known-answer vector from test_hashers.py.",
            )
        )
    return entries


def _bcrypt_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    import bcrypt

    source = SOURCES["bcrypt"]
    path = source.files[0]
    tree = ast.parse(_decode(_fetch(_raw_url(source, path))))
    vectors: list[tuple[bytes, bytes, bytes]] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "_test_vectors" for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        vectors = [tuple(row) for row in value]
        break
    if not vectors:
        raise ValueError("pyca/bcrypt _test_vectors list was not found")

    entries: list[dict[str, Any]] = []
    for password, _salt, raw in vectors:
        try:
            plaintext = password.decode("utf-8")
            raw_input = raw.decode("ascii")
        except UnicodeDecodeError:
            continue
        if "\x00" in plaintext or not raw_input.startswith("$2"):
            continue
        if not bcrypt.checkpw(password, raw):
            raise ValueError(f"bcrypt vector failed verification: {raw_input}")
        entries.append(
            _make_entry(
                source_key="bcrypt",
                source=source,
                path=path,
                line=11,
                mode=3200,
                plaintext=plaintext,
                raw_input=raw_input,
                meta=meta,
                verification="python:bcrypt.checkpw",
                notes="pyca/bcrypt known-answer vector with a fixed salt.",
            )
        )
    return entries


def _php_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    import bcrypt
    from passlib.hash import des_crypt, md5_crypt

    source = SOURCES["php"]
    crypt_path, verify_path = source.files
    crypt_text = _decode(_fetch(_raw_url(source, crypt_path)))
    verify_text = _decode(_fetch(_raw_url(source, verify_path)))
    vectors = (
        (
            crypt_path,
            7,
            1500,
            "rasmuslerdorf",
            "rl.3StKT.4T8M",
            "passlib:des_crypt",
        ),
        (
            crypt_path,
            9,
            500,
            "rasmuslerdorf",
            "$1$rasmusle$rISCgZzpwk3UhDidwXvin0",
            "passlib:md5_crypt",
        ),
        (
            verify_path,
            9,
            3200,
            "rasmuslerdorf",
            "$2a$07$usesomesillystringfore2uDLvp1Ii2e./U9C8sBjqp8I90dH6hi",
            "python:bcrypt.checkpw",
        ),
        (
            crypt_path,
            10,
            3200,
            "rasmuslerdorf",
            "$2a$07$rasmuslerd............nIdrcHdxcUxWomQX9j6kvERCFjTg7Ra",
            "python:bcrypt.checkpw",
        ),
    )
    entries: list[dict[str, Any]] = []
    for path, line, mode, plaintext, raw_input, verification in vectors:
        text = crypt_text if path == crypt_path else verify_text
        if raw_input not in text:
            raise ValueError(f"PHP vector missing from pinned source: {raw_input}")
        if verification == "passlib:des_crypt":
            ok = des_crypt.verify(plaintext, raw_input)
        elif verification == "passlib:md5_crypt":
            ok = md5_crypt.verify(plaintext, raw_input)
        else:
            ok = bcrypt.checkpw(plaintext.encode("utf-8"), raw_input.encode("ascii"))
        if not ok:
            raise ValueError(f"PHP vector failed verification: {raw_input}")
        entries.append(
            _make_entry(
                source_key="php",
                source=source,
                path=path,
                line=line,
                mode=mode,
                plaintext=plaintext,
                raw_input=raw_input,
                meta=meta,
                verification=verification,
                notes="PHP crypt()/password_verify() known-answer vector.",
            )
        )
    return entries


def _parse_openssl_blocks(text: str) -> list[tuple[int, dict[str, str]]]:
    blocks: list[tuple[int, dict[str, str]]] = []
    current: dict[str, str] = {}
    start = 1
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if current:
                blocks.append((start, current))
                current = {}
            continue
        if "=" in stripped:
            if not current:
                start = line_number
            key, value = stripped.split("=", 1)
            current[key.strip()] = value.strip()
    if current:
        blocks.append((start, current))
    return blocks


def _openssl_pbkdf2_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    source = SOURCES["openssl"]
    path = source.files[0]
    text = _decode(_fetch(_raw_url(source, path)))
    digest_modes = {"sha1": (12000, "sha1"), "sha256": (10900, "sha256"), "sha512": (12100, "sha512")}
    entries: list[dict[str, Any]] = []
    for line, block in _parse_openssl_blocks(text):
        if block.get("KDF") != "PBKDF2" or block.get("Result"):
            continue
        digest = block.get("Ctrl.digest", "").removeprefix("digest:")
        if digest not in digest_modes:
            continue
        if "Ctrl.pass" in block:
            password = block["Ctrl.pass"].removeprefix("pass:")
        elif "Ctrl.hexpass" in block:
            try:
                password = bytes.fromhex(block["Ctrl.hexpass"].removeprefix("hexpass:")).decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            continue
        if "Ctrl.salt" in block:
            salt = block["Ctrl.salt"].removeprefix("salt:")
        elif "Ctrl.hexsalt" in block:
            try:
                salt = bytes.fromhex(block["Ctrl.hexsalt"].removeprefix("hexsalt:")).decode("utf-8")
            except UnicodeDecodeError:
                continue
        else:
            continue
        if not password:
            continue
        try:
            iterations = int(block["Ctrl.iter"].removeprefix("iter:"))
            expected = bytes.fromhex(block["Output"])
        except (KeyError, ValueError):
            continue
        mode, algorithm = digest_modes[digest]
        actual = hashlib.pbkdf2_hmac(
            algorithm,
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
            dklen=len(expected),
        )
        if actual != expected:
            raise ValueError("OpenSSL PBKDF2 known-answer verification failed")
        raw_input = ":".join(
            (
                algorithm,
                str(iterations),
                base64.b64encode(salt.encode("utf-8")).decode("ascii"),
                base64.b64encode(expected).decode("ascii"),
            )
        )
        entries.append(
            _make_entry(
                source_key="openssl",
                source=source,
                path=path,
                line=line,
                mode=mode,
                plaintext=password,
                raw_input=raw_input,
                meta=meta,
                verification="python:hashlib.pbkdf2_hmac",
                notes="OpenSSL EVP KDF known-answer vector converted to Hashcat's canonical form.",
            )
        )
    return entries


def _openssl_scrypt_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    source = SOURCES["openssl"]
    path = source.files[1]
    text = _decode(_fetch(_raw_url(source, path)))
    entries: list[dict[str, Any]] = []
    for line, block in _parse_openssl_blocks(text):
        if block.get("KDF") != "id-scrypt" or block.get("Result"):
            continue
        password = block.get("Ctrl.pass", "").removeprefix("pass:")
        salt = block.get("Ctrl.salt", "").removeprefix("salt:")
        if not password or not salt:
            continue
        try:
            n = int(block["Ctrl.N"].removeprefix("n:"))
            r = int(block["Ctrl.r"].removeprefix("r:"))
            p = int(block["Ctrl.p"].removeprefix("p:"))
            expected = bytes.fromhex(block["Output"])
        except (KeyError, ValueError):
            continue
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt.encode("utf-8"),
            n=n,
            r=r,
            p=p,
            dklen=len(expected),
            maxmem=1024 * 1024 * 1024,
        )
        if actual != expected:
            raise ValueError("OpenSSL scrypt known-answer verification failed")
        raw_input = ":".join(
            (
                "SCRYPT",
                str(n),
                str(r),
                str(p),
                base64.b64encode(salt.encode("utf-8")).decode("ascii"),
                base64.b64encode(expected).decode("ascii"),
            )
        )
        entries.append(
            _make_entry(
                source_key="openssl",
                source=source,
                path=path,
                line=line,
                mode=8900,
                plaintext=password,
                raw_input=raw_input,
                meta=meta,
                verification="python:hashlib.scrypt",
                notes="OpenSSL scrypt known-answer vector converted to Hashcat's canonical SCRYPT form.",
            )
        )
    return entries


def _go_entries(meta: dict[str, Any]) -> list[dict[str, Any]]:
    import bcrypt

    source = SOURCES["go"]
    path = source.files[0]
    text = _decode(_fetch(_raw_url(source, path)))
    vectors = (
        (
            25,
            "allmine",
            "$2a$10$XajjQvNhvvRt5GSeFk1xFeyqRrsxkhBkUiQeg0dt.wU1qD4aFDcga",
        ),
        (
            32,
            "012345678901234567890123456789012345678901234567890123456",
            "$2a$10$XajjQvNhvvRt5GSeFk1xFe5l47dONXg781AmZtd869sO8zfsHuw7C",
        ),
    )
    entries: list[dict[str, Any]] = []
    for line, plaintext, raw_input in vectors:
        if raw_input not in text or f'"{plaintext}"' not in text:
            raise ValueError(f"Go bcrypt vector missing from pinned source: {raw_input}")
        if not bcrypt.checkpw(plaintext.encode("utf-8"), raw_input.encode("ascii")):
            raise ValueError(f"Go bcrypt vector failed verification: {raw_input}")
        entries.append(
            _make_entry(
                source_key="go",
                source=source,
                path=path,
                line=line,
                mode=3200,
                plaintext=plaintext,
                raw_input=raw_input,
                meta=meta,
                verification="python:bcrypt.checkpw",
                notes="golang.org/x/crypto/bcrypt known-answer vector.",
            )
        )
    return entries


def _passlib_entries(meta: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    import passlib
    from passlib.registry import get_crypt_handler

    passlib_root = Path(passlib.__file__).resolve().parent
    modules = (
        importlib.import_module("passlib.tests.test_handlers"),
        importlib.import_module("passlib.tests.test_handlers_pbkdf2"),
    )
    version = getattr(passlib, "__version__", "unknown")
    entries: list[dict[str, Any]] = []
    manifest: list[dict[str, Any]] = []
    seen_files: set[Path] = set()

    for module in modules:
        module_path = Path(inspect.getsourcefile(module) or "")
        if not module_path.exists():
            continue
        relative = module_path.relative_to(passlib_root).as_posix()
        if module_path not in seen_files:
            seen_files.add(module_path)
            manifest.append(
                {
                    "repo": "foss.heptapod.net/python-libs/passlib",
                    "commit": version,
                    "path": relative,
                    "sha256": hashlib.sha256(module_path.read_bytes()).hexdigest(),
                    "license": "BSD-3-Clause",
                    "url": f"https://pypi.org/project/passlib/{version}/",
                }
            )
        for class_name, (handler_name, mode) in PASSLIB_CLASSES.items():
            test_class = getattr(module, class_name, None)
            vectors = getattr(test_class, "known_correct_hashes", None)
            if not vectors:
                continue
            handler = get_crypt_handler(handler_name)
            class_line = inspect.getsourcelines(test_class)[1]
            selected = 0
            for vector in vectors:
                if selected >= MAX_PASSLIB_VECTORS:
                    break
                if not isinstance(vector, (tuple, list)) or len(vector) != 2:
                    continue
                plaintext, raw_input = vector
                if not isinstance(plaintext, str) or not isinstance(raw_input, str):
                    continue
                if not plaintext or not raw_input:
                    continue
                if handler_name == "phpass" and not raw_input.startswith("$P$"):
                    continue
                try:
                    verified = bool(handler.verify(plaintext, raw_input))
                except Exception:
                    continue
                if not verified:
                    continue
                entries.append(
                    _make_entry(
                        source_key="passlib",
                        source=Source(
                            "passlib",
                            "foss.heptapod.net/python-libs/passlib",
                            version,
                            "BSD-3-Clause",
                            (relative,),
                        ),
                        path=relative,
                        line=class_line,
                        mode=mode,
                        plaintext=plaintext,
                        raw_input=raw_input,
                        meta=meta,
                        verification=f"passlib:{handler_name}.verify",
                        notes=f"passlib {version} known_correct_hashes vector for {handler_name}.",
                    )
                )
                selected += 1
    return entries, manifest


def build_document() -> dict[str, Any]:
    warnings.filterwarnings("ignore")
    meta = _meta()
    entries: list[dict[str, Any]] = []
    source_manifest: list[dict[str, Any]] = []

    for key, source in SOURCES.items():
        for path in source.files:
            data = _fetch(_raw_url(source, path))
            source_manifest.append(
                {
                    "repo": source.repo,
                    "commit": source.commit,
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "license": source.license,
                    "url": _raw_url(source, path),
                }
            )

    extractors: tuple[Callable[[dict[str, Any]], list[dict[str, Any]]], ...] = (
        _django_entries,
        _bcrypt_entries,
        _php_entries,
        _openssl_pbkdf2_entries,
        _openssl_scrypt_entries,
        _go_entries,
    )
    for extractor in extractors:
        entries.extend(extractor(meta))

    passlib_vectors, passlib_manifest = _passlib_entries(meta)
    entries.extend(passlib_vectors)
    source_manifest.extend(passlib_manifest)

    deduplicated: list[dict[str, Any]] = []
    seen: set[tuple[int, str, str | None]] = set()
    for entry in entries:
        identity = (
            int(entry["mode"]),
            str(entry["raw_input"]),
            entry.get("expected_plaintext"),
        )
        if identity in seen:
            continue
        seen.add(identity)
        deduplicated.append(entry)
    deduplicated.sort(key=lambda item: (int(item["mode"]), item["upstream_repo"], item["id"]))

    ids = [entry["id"] for entry in deduplicated]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate crypto corpus entry ids")

    return {
        "schema_version": 1,
        "source": "crypto",
        "description": (
            "Known-answer hash vectors from pinned public crypto-library tests, "
            "converted to canonical Hashcat formats where needed and verified locally."
        ),
        "generated_from": "scripts/build_crypto_corpus.py",
        "sources": source_manifest,
        "counts": {
            "total": len(deduplicated),
            "with_plaintext": sum(1 for entry in deduplicated if entry["expected_plaintext"]),
            "usable_for_identification": sum(
                1 for entry in deduplicated if entry["usable_for_identification"]
            ),
            "usable_for_cracking": sum(
                1 for entry in deduplicated if entry["usable_for_cracking"]
            ),
            "verified": sum(1 for entry in deduplicated if entry["verified"]),
            "modes": len({int(entry["mode"]) for entry in deduplicated}),
            "upstreams": len({entry["upstream_repo"] for entry in deduplicated}),
        },
        "entries": deduplicated,
    }


def render(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit non-zero if the existing corpus is stale.",
    )
    args = parser.parse_args()

    document = build_document()
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
        f"wrote {args.output} ({counts['total']} verified vectors, "
        f"{counts['modes']} modes, {counts['upstreams']} upstreams)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
