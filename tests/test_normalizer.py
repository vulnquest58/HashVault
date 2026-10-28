# tests/test_normalizer.py
"""
Tests for hash normalization logic.
"""

import pytest
from hashvault.core.normalizer import normalize_hash, normalize_with_context, is_hex_only, is_base64_like


class TestNormalizer:
    """Test cases for hash normalization."""

    def test_simple_hash(self):
        """Test basic hash normalization."""
        result, username = normalize_hash("5f4dcc3b5aa765d61d8327deb882cf99")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username is None

    def test_hash_with_username(self):
        """Test username:hash format."""
        result, username = normalize_hash("john:5f4dcc3b5aa765d61d8327deb882cf99")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username == "john"

    def test_hash_username_with_colon_in_hash(self):
        """Test hash containing colon as part of format."""
        # Some hashes contain $ and colon within the hash itself
        result, username = normalize_hash("$1$salt$hashwith:colon")
        assert result == "$1$salt$hashwith:colon"
        assert username is None

    def test_hex_case_normalization(self):
        """Test hex-only hashes are lowercased."""
        result, username = normalize_hash("AABBCCDDEEFF00112233445566778899")
        assert result == "aabbccddeeff00112233445566778899"
        assert username is None

    def test_non_hex_case_preserved(self):
        """Test non-hex hashes preserve case (e.g., bcrypt, base64)."""
        result, username = normalize_hash("$2a$12$KIX6dF6XMqO0Z3qV.xf5.OW5b8n67Wt9xu3qLzqZqZqZqZqZqZq")
        assert result == "$2a$12$KIX6dF6XMqO0Z3qV.xf5.OW5b8n67Wt9xu3qLzqZqZqZqZqZqZq"
        assert username is None

    def test_whitespace_removal(self):
        """Test whitespace is removed."""
        result, username = normalize_hash(" 5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username is None

    def test_empty_string(self):
        """Test empty string handling."""
        result, username = normalize_hash("")
        assert result == ""
        assert username is None

    def test_username_with_special_chars(self):
        """Test usernames with special characters."""
        result, username = normalize_hash("user_name:5f4dcc3b5aa765d61d8327deb882cf99")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username == "user_name"

    def test_username_with_domain(self):
        """Test domain\\username format."""
        result, username = normalize_hash("DOMAIN\\user:5f4dcc3b5aa765d61d8327deb882cf99")
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username == "DOMAIN\\user"

    def test_domain_user_no_colon(self):
        """Test domain\\user without colon."""
        result, username = normalize_hash("DOMAIN\\user")
        assert result == "DOMAIN\\user"
        assert username is None

    def test_hex_only_detection(self):
        """Test hex-only detection."""
        assert is_hex_only("abcdef0123456789") is True
        assert is_hex_only("abcdefg") is False
        assert is_hex_only("1234567890") is True
        assert is_hex_only("$2a$") is False

    def test_base64_like_detection(self):
        """Test base64-like detection."""
        assert is_base64_like("ABCDEFGHIJKLMNOP") is True
        assert is_base64_like("abc/def+ghi=") is True
        assert is_base64_like("abcde") is False  # length not multiple of 4
        assert is_base64_like("abc/def+ghi=#") is False  # invalid char

    def test_normalize_with_context(self):
        """Test normalization with context."""
        result, username = normalize_with_context(
            "john:5f4dcc3b5aa765d61d8327deb882cf99",
            "pwdump"
        )
        assert result == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert username == "john"

        result, username = normalize_with_context("$1$salt$hash", "shadow")
        assert result == "$1$salt$hash"
        assert username is None
