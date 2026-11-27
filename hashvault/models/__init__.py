"""
Models package for HashVault containing ORM models and Pydantic schemas.
"""
from hashvault.models.orm import Base, CorpusEntryRecord, CrackAttempt, CrackedHash, CrackSession, IdentificationLog, Pattern, Rule, StrategyStat, Wordlist
from hashvault.models.schemas import IdentificationResult, PatternBase, CrackedHashBase

RuleRecord = Rule
WordlistRecord = Wordlist

__all__ = [
    "Base",
    "Pattern",
    "CorpusEntryRecord",
    "CrackAttempt",
    "CrackedHash",
    "CrackSession",
    "StrategyStat",
    "IdentificationLog",
    "Wordlist",
    "Rule",
    "RuleRecord",
    "WordlistRecord",
    "IdentificationResult",
    "PatternBase",
    "CrackedHashBase",
]
