# hashvault/models/orm.py
"""
SQLAlchemy ORM models for HashVault database.
All tables defined here with proper relationships and constraints.
"""

from datetime import datetime, timezone
from typing import Optional

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Integer, String, Text,
    UniqueConstraint, Index, Enum as SAEnum
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, declarative_base

from hashvault.core.registry import HashCategory, SessionStatus

Base = declarative_base()


class Pattern(Base):
    """Hash pattern definitions for identification."""
    __tablename__ = "patterns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    regex: Mapped[str] = mapped_column(Text)
    hashcat_mode: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    john_format: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    popularity: Mapped[int] = mapped_column(Integer, default=0, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    is_slow: Mapped[bool] = mapped_column(Boolean, default=False)
    category: Mapped[HashCategory] = mapped_column(
        SAEnum(HashCategory), index=True
    )
    min_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    max_length: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    prefix_hint: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    confidence_weight: Mapped[float] = mapped_column(Float, default=1.0)
    source_format_hints: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # JSON array

    # Relationships
    cracked_hashes: Mapped[list["CrackedHash"]] = relationship(
        back_populates="pattern"
    )

    __table_args__ = (
        Index("idx_pattern_popularity", "popularity"),
    )


class CrackedHash(Base):
    """Stores successfully cracked hashes."""
    __tablename__ = "cracked_hashes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    hash_value: Mapped[str] = mapped_column(Text, index=True)
    normalized_hash: Mapped[str] = mapped_column(Text, index=True)
    pattern_id: Mapped[int] = mapped_column(ForeignKey("patterns.id"))
    plaintext: Mapped[str] = mapped_column(Text)
    username: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_used: Mapped[str] = mapped_column(String)
    cracked_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    source: Mapped[str] = mapped_column(String, default="manual")
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    raw_input: Mapped[str] = mapped_column(Text, default="")

    # Relationships
    pattern: Mapped["Pattern"] = relationship(back_populates="cracked_hashes")

    __table_args__ = (
        UniqueConstraint(
            "normalized_hash", "pattern_id", "username",
            name="uq_hash_pattern_user"
        ),
        Index("idx_cracked_normalized", "normalized_hash"),
    )


class Wordlist(Base):
    """Wordlist definitions and metadata."""
    __tablename__ = "wordlists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    path: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    size: Mapped[int] = mapped_column(Integer, default=0)
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    line_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now
    )


class Rule(Base):
    """Hashcat/John rules definitions."""
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True, index=True)
    path: Mapped[str] = mapped_column(Text)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_type: Mapped[str] = mapped_column(String, default="hashcat")  # 'hashcat' or 'john'
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now
    )


class CrackSession(Base):
    """Session management for cracking operations."""
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String, primary_key=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    hashes_processed: Mapped[int] = mapped_column(Integer, default=0)
    cracked_count: Mapped[int] = mapped_column(Integer, default=0)
    outfile_path: Mapped[str] = mapped_column(Text)
    potfile_path: Mapped[str] = mapped_column(Text)
    status: Mapped[SessionStatus] = mapped_column(
        SAEnum(SessionStatus), default=SessionStatus.RUNNING
    )
    target_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    pattern_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("patterns.id"), nullable=True
    )
    tool_used: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class IdentificationLog(Base):
    """Logs hash identification decisions for quality tracking."""
    __tablename__ = "identification_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    normalized_hash: Mapped[str] = mapped_column(Text, index=True)
    resolved_method: Mapped[str] = mapped_column(String)
    chosen_pattern_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("patterns.id"), nullable=True
    )
    candidates_considered: Mapped[str] = mapped_column(Text)  # JSON
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    source_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


WordlistRecord = Wordlist
RuleRecord = Rule


class AnalysisLog(Base):
    """
    Records each deep-analysis pipeline run (CyberChef-style unwrapping +
    hash identification).  Used for quality tracking, confidence calibration,
    and future ML-based disambiguation.
    """
    __tablename__ = "analysis_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    raw_input: Mapped[str] = mapped_column(Text, index=True)
    """Original user input before any unwrapping."""

    finalized_input: Mapped[str] = mapped_column(Text)
    """Hash string after all encoding layers were peeled off."""

    unwrap_chain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """Human-readable chain: e.g. 'Base64 -> Hex -> (hash)'."""

    layers_applied: Mapped[int] = mapped_column(Integer, default=0)
    """Number of encoding layers that were decoded."""

    layers_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """JSON array of layer details [{operation, depth, input, output, confidence}]."""

    resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    """Whether identification produced a confident single result."""

    resolution_method: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    """ResolutionMethod value (prefix, single_match, confidence_margin, ambiguous)."""

    chosen_pattern_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("patterns.id"), nullable=True
    )
    """Winning pattern (if resolved)."""

    confidence_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    """Confidence of the chosen pattern."""

    candidates_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """JSON top-N candidates [{pattern_name, confidence}]."""

    source_context: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    """Serialised SourceContext that was passed in."""

    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)

    __table_args__ = (
        Index("idx_analysis_log_timestamp", "timestamp"),
        Index("idx_analysis_log_resolved", "resolved"),
    )


class CrackAttempt(Base):
    """One cracker execution, including failed and retried analysis branches."""

    __tablename__ = "crack_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    session_id: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    raw_input: Mapped[str] = mapped_column(Text)
    normalized_hash: Mapped[str] = mapped_column(Text, index=True)
    pattern_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    branch_chain: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tool_used: Mapped[str] = mapped_column(String)
    attempt_index: Mapped[int] = mapped_column(Integer, default=1)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    cached: Mapped[bool] = mapped_column(Boolean, default=False)
    elapsed_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    budget_seconds: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now, index=True)

    __table_args__ = (
        Index("idx_crack_attempt_hash", "normalized_hash"),
        Index("idx_crack_attempt_success", "success"),
    )


class StrategyStat(Base):
    """Aggregated contextual-bandit feedback for tool/pattern choices."""

    __tablename__ = "strategy_stats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feature_key: Mapped[str] = mapped_column(String, unique=True, index=True)
    pattern_name: Mapped[str] = mapped_column(String, index=True)
    tool: Mapped[str] = mapped_column(String, index=True)
    attack_mode: Mapped[str] = mapped_column(String, default="dictionary")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    successes: Mapped[int] = mapped_column(Integer, default=0)
    total_seconds: Mapped[float] = mapped_column(Float, default=0.0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now
    )

    @property
    def success_rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0


class CorpusEntryRecord(Base):
    """Persistent benchmark corpus entry with provenance metadata."""

    __tablename__ = "corpus_entries"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    source: Mapped[str] = mapped_column(String, index=True)
    mode: Mapped[int] = mapped_column(Integer, index=True)
    name: Mapped[str] = mapped_column(String)
    raw_input: Mapped[str] = mapped_column(Text)
    expected_plaintext: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(String, default="")
    username: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    domain: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    box: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    example_format: Mapped[str] = mapped_column(String, default="plain")
    slow_hash: Mapped[bool] = mapped_column(Boolean, default=False)
    is_binary: Mapped[bool] = mapped_column(Boolean, default=False)
    truncated: Mapped[bool] = mapped_column(Boolean, default=False)
    usable_for_identification: Mapped[bool] = mapped_column(Boolean, default=True)
    usable_for_cracking: Mapped[bool] = mapped_column(Boolean, default=True)
    unusable_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    upstream_repo: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    upstream_path: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    upstream_commit: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    upstream_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    license: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    verified: Mapped[bool] = mapped_column(Boolean, default=False)
    verification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=utc_now, onupdate=utc_now
    )

    __table_args__ = (
        Index("idx_corpus_source_mode", "source", "mode"),
    )
