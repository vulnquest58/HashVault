"""
HashVault configuration settings manager.
Loads settings from config/default.yaml and allows environment variable overrides via Pydantic BaseSettings.
"""
import json
import os
from pathlib import Path
import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
import platformdirs

from hashvault.core.registry import CrackTool


class PathsConfig(BaseModel):
    hashcat_bin: str = "hashcat"
    john_bin: str = "john"
    database: str = "db/hashvault.sqlite3"
    wordlist_dir: str = "data/wordlists"
    rules_dir: str = "data/rules"
    sessions_dir: str = "sessions"
    quick_wordlist: str = "data/wordlists/quick_1000.txt"


class TimeoutsConfig(BaseModel):
    fast_hash_seconds: int = 3600
    slow_hash_seconds: int = 86400
    gpu_detection_seconds: int = 15


class StrategyConfig(BaseModel):
    default_tool: CrackTool = CrackTool.HASHCAT
    max_rule_attempts: int = 3
    auto_select_confidence_threshold: float = 0.75
    auto_select_margin: float = 0.2
    enable_trial_disambiguation: bool = False
    # bounds for empirical disambiguation (built-in engine only)
    trial_max_candidates: int = 3
    trial_budget_seconds: float = 20.0
    # hashcat compute backend: auto | opencl | cuda | cpu
    hashcat_backend: str = "auto"
    # optional hashcat workloads: 1 (low) .. 4 (nightmare); 0 = hashcat default
    hashcat_workload_profile: int = 0
    # use the pure-Python fallback engine when external engines are unavailable
    builtin_enabled: bool = True
    # hard cap for built-in attacks; 0 = unlimited
    builtin_max_candidates: int = 0
    retry_alternatives: bool = True
    max_alternative_attempts: int = 3
    default_budget_seconds: float = 0.0
    adaptive_tool_selection: bool = True
    # keep session artifacts (potfile/outfile/target hash) after an attempt;
    # they contain recovered plaintext, so the default is to delete them
    keep_session_artifacts: bool = False
    # re-verify a cached plaintext before trusting it (slower, safer)
    verify_cache_entries: bool = True
    # also re-verify slow formats (bcrypt/argon2), which costs a full KDF
    verify_slow_hashes: bool = False


class MutationConfig(BaseModel):
    max_candidates: int = 500
    max_history_seeds: int = 500
    max_enrichment_seeds: int = 500
    include_years: bool = True
    years: list[int] = Field(default_factory=lambda: [2024, 2025, 2026])
    arabic_language: str = "auto"


class LLMConfig(BaseModel):
    enabled: bool = False
    base_url: str = "http://127.0.0.1:11434"
    model: str = "llama3.2"
    timeout_seconds: float = 20.0
    max_candidates: int = 25
    # HashVault promises that audit context never leaves the host.  Only
    # loopback endpoints are accepted unless this is explicitly enabled.
    allow_remote_endpoint: bool = False


class EnrichmentConfig(BaseModel):
    enabled: bool = False
    wordlist_paths: list[str] = Field(default_factory=list)


class OutputConfig(BaseModel):
    silent_by_default: bool = True
    log_file: str = "hashvault.log"
    log_level: str = "INFO"


class Config(BaseSettings):
    """Global configuration settings container."""
    model_config = SettingsConfigDict(
        env_prefix="HASHVAULT_",
        env_nested_delimiter="__",
        case_sensitive=False,
    )

    paths: PathsConfig = Field(default_factory=PathsConfig)
    timeouts: TimeoutsConfig = Field(default_factory=TimeoutsConfig)
    strategy: StrategyConfig = Field(default_factory=StrategyConfig)
    mutation: MutationConfig = Field(default_factory=MutationConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)
    enrichment: EnrichmentConfig = Field(default_factory=EnrichmentConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)

    def resolve_paths(self, base_dir: Path) -> None:
        """Resolve relative configuration paths relative to the specified base directory."""
        self.paths.database = str((base_dir / self.paths.database).resolve())
        self.paths.wordlist_dir = str((base_dir / self.paths.wordlist_dir).resolve())
        self.paths.rules_dir = str((base_dir / self.paths.rules_dir).resolve())
        self.paths.sessions_dir = str((base_dir / self.paths.sessions_dir).resolve())
        self.paths.quick_wordlist = str((base_dir / self.paths.quick_wordlist).resolve())


def _coerce_section(section: BaseModel, name: str, raw: str):
    """Rebuild ``section`` with one field replaced by an environment value."""
    data = section.model_dump()
    data[name] = raw
    try:
        return type(section)(**data)
    except Exception:
        pass
    # Complex types (list[str], list[int]) are documented as JSON in the
    # environment, e.g. HASHVAULT_ENRICHMENT__WORDLIST_PATHS='["a.txt"]'.
    if raw.strip()[:1] in ("[", "{"):
        try:
            data[name] = json.loads(raw)
            return type(section)(**data)
        except Exception:
            pass
    return None


def _apply_env_overrides(config: "Config") -> "Config":
    """Let ``HASHVAULT_*`` variables win over ``config/default.yaml``.

    ``Config(**yaml_data)`` gives init kwargs priority over the environment
    (pydantic-settings' default source order), so a value in the YAML file
    silently shadowed every environment override even though the README
    documents the opposite.  Re-applying the environment after construction
    restores the documented precedence: defaults < file < environment.
    """
    for section_name in type(config).model_fields:
        section = getattr(config, section_name, None)
        if not isinstance(section, BaseModel):
            continue
        for field_name in type(section).model_fields:
            env_key = f"HASHVAULT_{section_name.upper()}__{field_name.upper()}"
            raw = os.environ.get(env_key)
            if raw is None:
                continue
            updated = _coerce_section(section, field_name, raw)
            if updated is not None:
                setattr(config, section_name, updated)
    return config


def load_config(config_path: str | Path | None = None) -> Config:
    """
    Load configuration from default.yaml or a custom path, applying environment variable overrides.
    """
    if config_path is None:
        config_path = Path("config/default.yaml")
        if not config_path.exists():
            from hashvault.core.database import resolve_resource_path

            config_path = resolve_resource_path(config_path)

    config_file = Path(config_path)
    yaml_data = {}
    if config_file.exists():
        with open(config_file, "r", encoding="utf-8") as f:
            yaml_data = yaml.safe_load(f) or {}

    config = Config(**yaml_data)
    config = _apply_env_overrides(config)
    config.resolve_paths(config_file.parent.parent if config_file.exists() else Path.cwd())
    return config
