"""
Unit tests for source format extraction parsers.
"""
from hashvault.core.format_parsers import parse_source_file
from hashvault.core.registry import SourceFormat


def test_parse_pwdump():
    content = "administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    records = parse_source_file(content, SourceFormat.PWDUMP)
    assert len(records) == 1
    assert records[0].username == "administrator"
    assert records[0].normalized_hash == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_parse_shadow():
    content = "root:$6$saltsalt$8a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f:18000:0:99999:7:::\n"
    records = parse_source_file(content, SourceFormat.SHADOW)
    assert len(records) == 1
    assert records[0].username == "root"
    assert records[0].normalized_hash.startswith("$6$saltsalt$")


def test_parse_responder_ntlmv2():
    content = "user::domain:1122334455667788:0102030405060708:blobdata"
    records = parse_source_file(content, SourceFormat.RESPONDER_NTLMV2)
    assert len(records) == 1
    assert records[0].username == "user"
