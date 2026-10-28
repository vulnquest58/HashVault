"""
Tests for canonicalizer + router integration and the updated orchestrator.
"""

from __future__ import annotations

import pytest

from hashvault.core.canonicalizer import (
    CrackPayload,
    ToolCapability,
    canonicalize,
    capability_for,
    split_credentials,
)
from hashvault.core.registry import CrackTool, SourceFormat
from hashvault.core.router import RouteDecision, route_tool
from hashvault.exceptions import ToolSelectionError


# ---------------------------------------------------------------------------
# split_credentials
# ---------------------------------------------------------------------------


class TestSplitCredentials:
    def test_no_colon_returns_none_user(self):
        user, h = split_credentials("5f4dcc3b5aa765d61d8327deb882cf99")
        assert user is None
        assert h == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_simple_user_colon_hash(self):
        user, h = split_credentials("admin:5f4dcc3b5aa765d61d8327deb882cf99")
        # Without pattern, short non-hex prefix is treated as username.
        assert user == "admin"
        assert h == "5f4dcc3b5aa765d61d8327deb882cf99"

    def test_label_prefix_preserved(self):
        raw = "file.zip:$pkzip$something"
        user, h = split_credentials(raw)
        assert user is None
        assert h == raw

    def test_archive_label_prefixes(self):
        for prefix in ("$7z$", "$rar", "$pkzip", "$keepass$", "$pdf$", "$office$"):
            raw = f"file:{prefix}abc"
            u, h = split_credentials(raw)
            assert u is None, f"Expected no user for {prefix}"
            assert h == raw

    def test_long_hex_prefix_not_a_username(self):
        """A long all-hex prefix is the hash body, not a username."""
        raw = "5f4dcc3b5aa765d61d8327deb882cf99:extra"
        user, h = split_credentials(raw)
        assert user is None
        assert h == raw


# ---------------------------------------------------------------------------
# canonicalize
# ---------------------------------------------------------------------------


class TestCanonicalize:
    def test_bare_hash_no_username(self):
        payload = canonicalize("5f4dcc3b5aa765d61d8327deb882cf99")
        assert payload.username is None
        assert payload.canonical_hash == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert payload.needs_username_flag is False

    def test_user_hash_marks_username_flag(self):
        payload = canonicalize("admin:5f4dcc3b5aa765d61d8327deb882cf99")
        assert payload.username == "admin"
        assert payload.needs_username_flag is True

    def test_capability_none_pattern(self):
        payload = canonicalize("abc123")
        assert payload.capability.hashcat is False
        assert payload.capability.john is False

    def test_capability_with_pattern_mock(self):
        class MockPattern:
            name = "MD5"
            hashcat_mode = 0
            john_format = "raw-md5"

        payload = canonicalize("5f4dcc3b5aa765d61d8327deb882cf99", pattern=MockPattern())
        assert payload.capability.hashcat is True
        assert payload.capability.john is True

    def test_archive_payload_preserved(self):
        raw = "archive.zip:$pkzip$2*1*abc*def*0*1*2*3*ABCDEF*0*0*0*"
        payload = canonicalize(raw)
        assert payload.username is None
        assert payload.canonical_hash == raw  # nothing stripped

    def test_postgresql_md5_reorders_for_mode_12(self):
        class MockPattern:
            name = "PostgreSQL MD5"
            hashcat_mode = 12
            john_format = None

        payload = canonicalize(
            "postgres:md532e12f215ba27cb750c9e093ce4b5127",
            pattern=MockPattern(),
        )
        assert payload.username == "postgres"
        assert payload.canonical_hash == "32e12f215ba27cb750c9e093ce4b5127"
        assert payload.hashcat_input == "32e12f215ba27cb750c9e093ce4b5127:postgres"


# ---------------------------------------------------------------------------
# capability_for
# ---------------------------------------------------------------------------


class TestCapabilityFor:
    def test_hashcat_only(self):
        class P:
            hashcat_mode = 1000
            john_format = None
        cap = capability_for(P())
        assert cap.hashcat is True
        assert cap.john is False

    def test_john_only(self):
        class P:
            hashcat_mode = None
            john_format = "raw-md5"
        cap = capability_for(P())
        assert cap.hashcat is False
        assert cap.john is True

    def test_both(self):
        class P:
            hashcat_mode = 0
            john_format = "raw-md5"
        cap = capability_for(P())
        assert cap.hashcat is True
        assert cap.john is True

    def test_neither(self):
        class P:
            hashcat_mode = None
            john_format = None
        cap = capability_for(P())
        assert not cap.available()

    def test_builtin_capability(self):
        class P:
            name = "MD5"
            hashcat_mode = 0
            john_format = None
        cap = capability_for(P())
        assert cap.builtin is True


# ---------------------------------------------------------------------------
# route_tool
# ---------------------------------------------------------------------------


class TestRouteTool:
    def _cap(self, hc=True, jn=True):
        return ToolCapability(hashcat=hc, john=jn)

    def test_explicit_hashcat_honored(self):
        dec = route_tool(self._cap(), requested=CrackTool.HASHCAT)
        assert dec.tool == CrackTool.HASHCAT

    def test_explicit_john_honored(self):
        dec = route_tool(self._cap(), requested=CrackTool.JOHN)
        assert dec.tool == CrackTool.JOHN

    def test_explicit_tool_string_is_coerced(self):
        dec = route_tool(self._cap(), requested="john")  # type: ignore[arg-type]
        assert dec.tool == CrackTool.JOHN

    def test_explicit_hashcat_unavailable_raises(self):
        cap = self._cap(hc=False, jn=True)
        with pytest.raises(ToolSelectionError):
            route_tool(cap, requested=CrackTool.HASHCAT)

    def test_explicit_john_unavailable_raises(self):
        cap = self._cap(hc=True, jn=False)
        with pytest.raises(ToolSelectionError):
            route_tool(cap, requested=CrackTool.JOHN)

    def test_auto_prefers_hashcat_when_both(self):
        dec = route_tool(self._cap(), requested=CrackTool.AUTO)
        assert dec.tool == CrackTool.HASHCAT

    def test_auto_prefers_john_when_prefer_john(self):
        dec = route_tool(self._cap(), requested=CrackTool.AUTO, prefer_john=True)
        assert dec.tool == CrackTool.JOHN

    def test_auto_only_hashcat_available(self):
        cap = self._cap(hc=True, jn=False)
        dec = route_tool(cap, requested=CrackTool.AUTO)
        assert dec.tool == CrackTool.HASHCAT

    def test_auto_only_john_available(self):
        cap = self._cap(hc=False, jn=True)
        dec = route_tool(cap, requested=CrackTool.AUTO)
        assert dec.tool == CrackTool.JOHN

    def test_auto_neither_raises(self):
        cap = self._cap(hc=False, jn=False)
        with pytest.raises(ToolSelectionError):
            route_tool(cap, requested=CrackTool.AUTO)

    def test_default_fallback_hashcat_unavailable(self):
        """When default is hashcat but unavailable, fall back to john."""
        cap = self._cap(hc=False, jn=True)
        dec = route_tool(cap, default_tool=CrackTool.HASHCAT)
        assert dec.tool == CrackTool.JOHN

    def test_default_fallback_john_unavailable(self):
        """When default is john but unavailable, fall back to hashcat."""
        cap = self._cap(hc=True, jn=False)
        dec = route_tool(cap, default_tool=CrackTool.JOHN)
        assert dec.tool == CrackTool.HASHCAT

    def test_no_tool_available_raises(self):
        cap = self._cap(hc=False, jn=False)
        with pytest.raises(ToolSelectionError):
            route_tool(cap, default_tool=CrackTool.HASHCAT)

    def test_route_decision_summary(self):
        cap = self._cap()
        dec = route_tool(cap, requested=CrackTool.HASHCAT)
        summary = dec.summary()
        assert "hashcat" in summary.lower()

    def test_none_capability_safe(self):
        """route_tool with None capability treats it as empty ToolCapability."""
        # None capability → no hashcat, no john → ToolSelectionError on AUTO.
        with pytest.raises(ToolSelectionError):
            route_tool(None, requested=CrackTool.AUTO)  # type: ignore

    def test_explicit_builtin_honored(self):
        cap = ToolCapability(builtin=True)
        dec = route_tool(cap, requested=CrackTool.BUILTIN)
        assert dec.tool == CrackTool.BUILTIN

    def test_explicit_builtin_unavailable_raises(self):
        with pytest.raises(ToolSelectionError):
            route_tool(ToolCapability(builtin=True), requested=CrackTool.BUILTIN, builtin_available=False)

    def test_auto_falls_back_to_builtin(self):
        cap = ToolCapability(builtin=True)
        dec = route_tool(cap, requested=CrackTool.AUTO)
        assert dec.tool == CrackTool.BUILTIN

    def test_auto_skips_unavailable_external_engines(self):
        cap = ToolCapability(hashcat=True, john=True, builtin=True)
        dec = route_tool(
            cap,
            requested=CrackTool.AUTO,
            hashcat_available=False,
            john_available=False,
        )
        assert dec.tool == CrackTool.BUILTIN


# ---------------------------------------------------------------------------
# Analysis log persistence (unit — uses in-memory DB)
# ---------------------------------------------------------------------------


def test_analysis_log_persisted(test_db_session):
    """AnalysisLog row is written after analyze_input() call."""
    from hashvault.analysis.analyzer import analyze_input
    from hashvault.config import load_config
    from hashvault.models.orm import AnalysisLog

    config = load_config()
    MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"

    res = analyze_input(MD5, test_db_session, config, persist_log=True)

    rows = test_db_session.query(AnalysisLog).all()
    assert len(rows) >= 1
    row = rows[-1]
    assert row.raw_input == MD5
    assert row.finalized_input == MD5
    assert row.layers_applied == 0


def test_analysis_log_wrapped_input(test_db_session):
    """When a Base64-wrapped hash is analyzed, the log captures the chain."""
    import base64
    from hashvault.analysis.analyzer import analyze_input
    from hashvault.config import load_config
    from hashvault.models.orm import AnalysisLog

    config = load_config()
    MD5 = "5f4dcc3b5aa765d61d8327deb882cf99"
    wrapped = base64.b64encode(MD5.encode()).decode()

    analyze_input(wrapped, test_db_session, config, persist_log=True)

    rows = test_db_session.query(AnalysisLog).all()
    last = rows[-1]
    assert last.raw_input == wrapped
    assert last.finalized_input == MD5
    assert last.layers_applied >= 1
    assert "Base64" in (last.unwrap_chain or "")
