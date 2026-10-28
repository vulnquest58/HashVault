# hashvault/models/schemas.py
"""
Pydantic schemas for HashVault DTOs.
Completely separate from ORM models.
"""

from datetime import datetime, timezone

def utc_now() -> datetime:
    return datetime.now(timezone.utc)
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict, field_validator

from hashvault.core.registry import (
    HashCategory, SourceFormat, CrackTool, OutputFormat,
    SessionStatus, ResolutionMethod
)


class PatternBase(BaseModel):
    """Base schema for hash patterns."""
    name: str
    regex: str
    hashcat_mode: Optional[int] = None
    john_format: Optional[str] = None
    popularity: int = 0
    description: str = ""
    is_slow: bool = False
    category: HashCategory
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    prefix_hint: Optional[str] = None
    confidence_weight: float = 1.0
    source_format_hints: Optional[List[SourceFormat]] = None

    @field_validator("source_format_hints", mode="before")
    @classmethod
    def parse_json_hints(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip():
            import json as json_lib
            try:
                return json_lib.loads(v)
            except Exception:
                return v
        return v


class PatternCreate(PatternBase):
    """Schema for creating a new pattern."""
    pass


class Pattern(PatternBase):
    """Complete pattern schema with ID."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None


PatternSchema = Pattern


class CrackedHashBase(BaseModel):
    """Base schema for cracked hashes."""
    hash_value: str
    normalized_hash: str
    pattern_id: int
    plaintext: str
    username: Optional[str] = None
    tool_used: str
    source: str = "manual"
    notes: Optional[str] = None
    raw_input: str = ""


class CrackedHashCreate(CrackedHashBase):
    """Schema for creating a cracked hash entry."""
    pass


class CrackedHash(CrackedHashBase):
    """Complete cracked hash schema with timestamps."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    cracked_at: datetime = Field(default_factory=utc_now)
    pattern: Optional[Pattern] = None


CrackedHashSchema = CrackedHash


class SessionBase(BaseModel):
    """Base schema for crack sessions."""
    session_id: str
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: Optional[datetime] = None
    hashes_processed: int = 0
    cracked_count: int = 0
    outfile_path: str
    potfile_path: str
    status: SessionStatus = SessionStatus.RUNNING
    target_hash: Optional[str] = None
    pattern_id: Optional[int] = None
    tool_used: Optional[str] = None
    error_message: Optional[str] = None


class SessionCreate(SessionBase):
    """Schema for creating a new session."""
    pass


class Session(SessionBase):
    """Complete session schema with optional relationships."""
    model_config = ConfigDict(from_attributes=True)


CrackSessionSchema = Session


class WordlistBase(BaseModel):
    """Base schema for wordlists."""
    name: str
    path: str
    description: Optional[str] = None
    size: int = 0
    size_bytes: int = 0
    line_count: Optional[int] = None
    source_url: Optional[str] = None
    version: Optional[str] = None


class WordlistCreate(WordlistBase):
    """Schema for creating a wordlist entry."""
    pass


class Wordlist(WordlistBase):
    """Complete wordlist schema."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


WordlistDTO = Wordlist


class RuleBase(BaseModel):
    """Base schema for rules."""
    name: str
    path: str
    description: Optional[str] = None
    tool_type: str = "hashcat"
    source_url: Optional[str] = None
    version: Optional[str] = None


class RuleCreate(RuleBase):
    """Schema for creating a rule entry."""
    pass


class Rule(RuleBase):
    """Complete rule schema."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


RuleDTO = Rule


class SourceContext(BaseModel):
    """Contextual metadata accompanying a hash input to guide candidate scoring."""
    origin_file: Optional[str] = None
    associated_format: Optional[SourceFormat] = None
    domain_prefix: bool = False
    user_declared_hint: Optional[HashCategory] = None


class CandidateDTO(BaseModel):
    """Candidate result produced during hash pattern identification scoring."""
    pattern: Pattern
    confidence: float = Field(ge=0.0, le=1.0)


class IdentificationResult(BaseModel):
    """Result of hash identification."""
    candidates: List[Dict[str, Any]] = []
    resolved: bool = False
    method: ResolutionMethod = ResolutionMethod.AMBIGUOUS
    chosen_pattern: Optional[Pattern] = None
    confidence_score: Optional[float] = None


class CrackRequest(BaseModel):
    """Request for cracking operation."""
    hash_value: str
    normalized_hash: str
    username: Optional[str] = None
    pattern_id: int
    wordlist_name: Optional[str] = None
    rule_name: Optional[str] = None
    tool: CrackTool = CrackTool.AUTO
    timeout: Optional[int] = None
    auto_select: bool = False


class CrackResult(BaseModel):
    """Result of cracking operation."""
    success: bool
    plaintext: Optional[str] = None
    pattern_id: Optional[int] = None
    pattern_name: Optional[str] = None
    tool_used: Optional[str] = None
    error_message: Optional[str] = None
    session_id: Optional[str] = None
    duration_seconds: Optional[float] = None
    confidence: Optional[float] = None


class AnalysisLayer(BaseModel):
    """A single decoded layer in the deep-analysis trace."""

    operation: str
    depth: int
    input_text: str = ""
    output_text: str = ""
    confidence: float = 0.0


class AnalysisResult(BaseModel):
    """Structured result of the deep-analysis pipeline."""

    raw_input: str
    finalized_input: str = ""
    unwrap_chain: str = ""
    layers: List[AnalysisLayer] = []
    resolved: bool = False
    method: str = "ambiguous"
    chosen_pattern: Optional[str] = None
    confidence_score: Optional[float] = None
    candidates: List[Dict[str, Any]] = []


class StatsResponse(BaseModel):
    """Statistics response."""
    total_hashes_cracked: int = 0
    unique_hashes: int = 0
    patterns_used: Dict[str, int] = {}
    most_common_tool: Optional[str] = None
    success_rate: float = 0.0
    average_time_per_hash: Optional[float] = None
    total_sessions: int = 0
    active_sessions: int = 0
