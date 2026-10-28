"""
Tests for the CyberChef-style deep-analysis pipeline (hashvault/analysis/).

Covers: encoding-layer unwrapping (Base64/Hex/URL/...), recursion guards,
integration with the identification engine, and the public analyze_input API.
"""

import base64
import binascii
from io import StringIO
from urllib.parse import quote

import pytest
from rich.console import Console

from hashvault.analysis import analyze_input, prepare_input, unpack_layers
from hashvault.analysis.live import RichAnalysisLive
from hashvault.config import load_config

# A canonical MD5 (32 hex chars) used across fixtures.
MD5_HEX = "5f4dcc3b5aa765d61d8327deb882cf99"


def _base64(s: bytes) -> str:
    return base64.b64encode(s).decode("ascii")


def _hex_bytes(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


# --------------------------------------------------------------------------- #
# Recipe / unwrapping layer tests
# --------------------------------------------------------------------------- #

def test_unpack_single_base64_layer():
    payload = _base64(MD5_HEX.encode())
    trace = unpack_layers(payload)
    assert trace.layers_applied == 1
    assert trace.layers[0].operation == "Base64"
    assert trace.finalized_input == MD5_HEX


def test_unpack_hex_layer():
    # "password" as ASCII hex -> after peel it becomes readable text.
    payload = _hex_bytes(b"password")
    trace = unpack_layers(payload)
    # First layer must be HexDecode and produce "password"
    assert trace.layers_applied >= 1
    assert trace.layers[0].operation == "Hex"
    assert trace.layers[0].output_text == "password"


def test_unpack_nested_base64_then_hex():
    # First layer: base64; inner content is a 32-char hex hash.
    inner = MD5_HEX
    payload = _base64(inner.encode())
    trace = unpack_layers(payload, max_depth=4)
    assert trace.layers_applied >= 1
    assert len(trace.finalized_input) == 32
    assert set(trace.finalized_input) <= set("0123456789abcdef")


def test_unpack_url_encoded():
    # URL-encoding only changes non-unreserved characters; use specials.
    original = "Hello world & x+1"
    payload = quote(original)
    assert payload != original
    trace = unpack_layers(payload)
    # Layer 1 must be URLDecode and must produce the original text
    assert trace.layers[0].operation == "URLDecode"
    assert trace.layers[0].output_text == original


def test_unpack_does_not_loop_forever():
    # Plain readable hash must not be consumed by any operation.
    payload = MD5_HEX
    trace = unpack_layers(payload, max_depth=20)
    assert trace.finalized_input == MD5_HEX
    assert trace.layers_applied == 0


def test_unpack_bounded_depth():
    # Force a pathological many-layer input; depth must be respected.
    payload = MD5_HEX
    for _ in range(15):
        payload = _base64(payload.encode())
    trace = unpack_layers(payload, max_depth=5)
    assert trace.layers_applied <= 5


# --------------------------------------------------------------------------- #
# Public API + identification integration
# --------------------------------------------------------------------------- #

def test_analyze_input_clean_hash_resolves(test_db_session):
    config = load_config()
    res = analyze_input(MD5_HEX, test_db_session, config)
    assert res.finalized_input == MD5_HEX
    assert res.trace.layers_applied == 0
    names = [c.pattern.name for c in res.identification.candidates]
    assert "MD5" in names


def test_analyze_input_wrapped_hash_resolves(test_db_session):
    config = load_config()
    wrapped = _base64(MD5_HEX.encode())
    res = analyze_input(wrapped, test_db_session, config, max_layers=6)
    assert res.trace.layers_applied >= 1
    assert res.finalized_input == MD5_HEX
    names = [c.pattern.name for c in res.identification.candidates]
    assert "MD5" in names


def test_analyze_result_dict_shape(test_db_session):
    config = load_config()
    res = analyze_input(_base64(MD5_HEX.encode()), test_db_session, config)
    d = res.to_dict()
    assert d["finalized_input"] == MD5_HEX
    assert d["layers_applied"] >= 1
    assert "layers" in d
    assert d["layers"][0]["operation"] == "Base64"


def test_handoff_exposes_ranked_hypotheses():
    handoff = prepare_input(_base64(MD5_HEX.encode()))
    data = handoff.to_trace_dict()
    assert data["selected"] == MD5_HEX
    assert data["branches"]
    assert data["branches"][0]["selected"] is True
    assert data["branches"][0]["finalized_input"] == MD5_HEX
    assert all("chain" in branch for branch in data["branches"])


def test_live_analysis_listener_renders_and_finishes():
    output = StringIO()
    console = Console(file=output, force_terminal=False, width=120, highlight=False)
    with RichAnalysisLive(console=console) as view:
        handoff = prepare_input(_base64(MD5_HEX.encode()), listener=view)
    assert handoff.primary == MD5_HEX
    assert view.best is not None
    assert view.terminals
    assert view.nodes > 0
    assert view.finished is True
    rendered = output.getvalue()
    assert "HashVault Deep Analysis" in rendered
    assert MD5_HEX in rendered
