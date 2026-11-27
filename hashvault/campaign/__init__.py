"""Proof-carrying corpus recovery campaigns."""

from hashvault.campaign.certificate import (
    build_certificate,
    generate_certificate_keypair,
    sign_certificate,
    verify_certificate,
    write_certificate,
)
from hashvault.campaign.engine import CampaignEngine
from hashvault.campaign.ingest import (
    CorpusRecord,
    parse_corpus_file,
    parse_corpus_text,
)
from hashvault.campaign.models import (
    CampaignPlan,
    CampaignReport,
    Evidence,
    Recovery,
    Stage,
    Target,
)

__all__ = [
    "CampaignEngine",
    "CampaignPlan",
    "CampaignReport",
    "CorpusRecord",
    "Evidence",
    "Recovery",
    "Stage",
    "Target",
    "build_certificate",
    "generate_certificate_keypair",
    "parse_corpus_file",
    "parse_corpus_text",
    "sign_certificate",
    "verify_certificate",
    "write_certificate",
]
