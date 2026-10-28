# hashvault/exceptions.py
"""
Hierarchical exception system for HashVault.
All custom exceptions inherit from HashVaultError base.
"""


class HashVaultError(Exception):
    """Base exception for all HashVault errors."""
    pass


class ToolNotFoundError(HashVaultError):
    """Raised when required external tool (hashcat/john) is not found."""
    def __init__(self, tool_name: str, custom_path: str | None = None):
        self.tool_name = tool_name
        self.custom_path = custom_path
        msg = f"External tool '{tool_name}' not found" + (f" at '{custom_path}'" if custom_path else "")
        super().__init__(msg)


class NoCandidateError(HashVaultError):
    """Raised when no hash pattern matches the input."""
    pass


class AmbiguousHashError(HashVaultError):
    """Raised when multiple patterns match with similar confidence."""
    pass


class CrackTimeoutError(HashVaultError):
    """Raised when cracking operation exceeds timeout."""
    pass


class InvalidHashError(HashVaultError):
    """Raised when hash format is invalid or malformed."""
    pass


class DatabaseError(HashVaultError):
    """Raised for database-related errors."""
    pass


class ConfigurationError(HashVaultError):
    """Raised for configuration-related errors."""
    pass


ConfigError = ConfigurationError


class InvalidPatternError(HashVaultError):
    """Raised when pattern file validation fails."""
    pass


class ResourceNotFoundError(HashVaultError):
    """Raised when required resource (wordlist/rule) is missing."""
    pass


class SessionError(HashVaultError):
    """Raised when session management fails."""
    pass


class UnauthorizedOperationError(HashVaultError):
    """Raised when unauthorized operation is attempted."""
    pass


class FormatParserError(HashVaultError):
    """Raised when source format parsing fails."""
    pass


class WordlistNotFoundError(HashVaultError):
    """Raised when wordlist is missing."""
    pass


class RuleNotFoundError(HashVaultError):
    """Raised when rule file is missing."""
    pass


class ToolSelectionError(HashVaultError):
    """Raised when no compatible external tool can be selected."""
    pass
