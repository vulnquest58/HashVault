"""Run legacy John ``*2john`` helpers under Python 3.

Several helpers bundled with John jumbo were written for Python 2 but parse as
Python 3.  This runner applies a narrow compatibility layer and executes the
selected helper in an isolated subprocess.
"""

from __future__ import annotations

import base64
import builtins
import functools
import pickle
import re
import sys
from pathlib import Path


def _hex_encode(value: object) -> str:
    if isinstance(value, str):
        value = value.encode("latin-1")
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytearray):
        value = bytes(value)
    if not isinstance(value, bytes):
        raise TypeError(f"expected bytes-like value, got {type(value).__name__}")
    return value.hex()


def _hex_decode(value: object) -> bytes:
    if isinstance(value, bytes):
        value = value.decode("ascii")
    if not isinstance(value, str):
        raise TypeError(f"expected str or bytes, got {type(value).__name__}")
    return bytes.fromhex(value)


def _install_runtime_shims() -> None:
    base64.decodestring = base64.decodebytes
    base64.encodestring = base64.encodebytes
    builtins.xrange = range
    builtins.raw_input = input
    builtins.long = int
    builtins.unicode = str
    builtins.unichr = chr
    builtins.basestring = str
    builtins.file = open
    builtins.reduce = functools.reduce
    sys.maxint = sys.maxsize
    sys.setdefaultencoding = lambda _encoding: None
    sys.exc_clear = lambda: None
    sys.modules.setdefault("cPickle", pickle)
    sys.modules.setdefault("ConfigParser", __import__("configparser"))
    sys.modules.setdefault("StringIO", __import__("io"))
    sys.modules.setdefault("cStringIO", __import__("io"))


_HEX_ENCODE = re.compile(
    r"([A-Za-z_][\w\.]*(?:\[[^\[\]]*\])?)\.encode\((['\"])hex\2\)"
)
_HEX_DECODE = re.compile(
    r"([A-Za-z_][\w\.]*(?:\[[^\[\]]*\])?)\.decode\((['\"])hex\2\)"
)


def _port_source(source: str) -> str:
    source = _HEX_ENCODE.sub(r"_hv_hex_encode(\1)", source)
    source = _HEX_DECODE.sub(r"_hv_hex_decode(\1)", source)
    for method in ("iteritems", "iterkeys", "itervalues"):
        source = re.sub(rf"\.{method}\(\)", f".{method[4:]}()", source)
    return source


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print(
            "usage: john_py3_compat.py CONVERTER INPUT [converter arguments...]",
            file=sys.stderr,
        )
        return 2
    converter_arg, input_arg, *extra = args
    converter = Path(converter_arg).resolve()
    target = Path(input_arg).resolve()
    if not converter.is_file():
        print(f"converter not found: {converter}", file=sys.stderr)
        return 2
    if not target.exists():
        print(f"input not found: {target}", file=sys.stderr)
        return 2

    _install_runtime_shims()
    try:
        source = converter.read_text(encoding="utf-8-sig")
    except UnicodeDecodeError:
        source = converter.read_text(encoding="utf-8", errors="replace")
    source = _port_source(source)

    sys.argv = [str(converter), str(target), *extra]
    sys.path.insert(0, str(converter.parent))
    namespace = {
        "__name__": "__main__",
        "__file__": str(converter),
        "__package__": None,
        "__spec__": None,
        "__builtins__": builtins,
        "_hv_hex_encode": _hex_encode,
        "_hv_hex_decode": _hex_decode,
    }
    code = compile(source, str(converter), "exec")
    exec(code, namespace)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
