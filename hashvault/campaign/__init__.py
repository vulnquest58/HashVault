"""Proof-carrying corpus recovery campaigns."""

from hashvault.campaign.certificate import (
    build_certificate,
    generate_certificate_keypair,
    sign_certificate,
    verify_certificate,
    write_certificate,
)
from hashvault.campaign.checkpoint import (
    CheckpointError,
    load_checkpoint,
    write_checkpoint,
)
from hashvault.campaign.engine import CampaignEngine
from hashvault.campaign.ingest import (
    CorpusRecord,
    iter_corpus_file,
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
from hashvault.campaign.potfile import (
    PotfileEntry,
    load_potfile,
    parse_potfile_text,
    potfile_mapping,
)

__all__ = [
    "CampaignEngine",
    "CampaignPlan",
    "CampaignReport",
    "CheckpointError",
    "CorpusRecord",
    "Evidence",
    "PotfileEntry",
    "Recovery",
    "Stage",
    "Target",
    "build_certificate",
    "generate_certificate_keypair",
    "iter_corpus_file",
    "load_checkpoint",
    "load_potfile",
    "parse_corpus_file",
    "parse_corpus_text",
    "parse_potfile_text",
    "potfile_mapping",
    "sign_certificate",
    "verify_certificate",
    "write_certificate",
    "write_checkpoint",
]
