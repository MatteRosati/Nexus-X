from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_api_key: SecretStr
    app_env: Literal["development", "test", "production"] = "production"
    enable_api_docs: bool = False
    log_level: str = "INFO"

    database_url: str = "sqlite:///./database/easm.db"

    easm_allowed_domains: str = ""
    allow_arbitrary_targets: bool = False
    max_queued_scans: int = Field(default=100, ge=1, le=10000)
    worker_concurrency: int = Field(default=2, ge=1, le=32)
    worker_poll_seconds: float = Field(default=2.0, ge=0.2, le=60)
    scan_stale_after_minutes: int = Field(default=60, ge=5, le=1440)

    collector_timeout_seconds: float = Field(default=20.0, ge=2, le=120)
    crtsh_max_response_bytes: int = Field(default=5_242_880, ge=65_536, le=52_428_800)
    crtsh_max_entries: int = Field(default=5000, ge=100, le=50000)

    censys_enabled: bool = False
    censys_pat: SecretStr | None = None
    censys_organization_id: str | None = None
    censys_max_results: int = Field(default=100, ge=1, le=100)
    censys_max_concurrency: int = Field(default=1, ge=1, le=25)

    zoomeye_enabled: bool = False
    zoomeye_api_key: SecretStr | None = None
    zoomeye_max_results: int = Field(default=50, ge=1, le=500)
    zoomeye_max_concurrency: int = Field(default=1, ge=1, le=5)

    leaklookup_enabled: bool = False
    leaklookup_api_key: SecretStr | None = None

    trusted_hosts: str = "localhost,127.0.0.1"
    cors_origins: str = ""

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
            raise ValueError("Unsupported LOG_LEVEL")
        return normalized

    @model_validator(mode="after")
    def validate_security_settings(self):
        key = self.app_api_key.get_secret_value()
        if len(key) < 32:
            raise ValueError("APP_API_KEY must contain at least 32 characters")
        if self.app_env == "production" and key.startswith("REPLACE_"):
            raise ValueError("APP_API_KEY still contains the example placeholder")
        if self.censys_enabled and not self.censys_pat:
            raise ValueError("CENSYS_ENABLED=true requires CENSYS_PAT")
        if self.zoomeye_enabled and not self.zoomeye_api_key:
            raise ValueError("ZOOMEYE_ENABLED=true requires ZOOMEYE_API_KEY")
        if self.leaklookup_enabled and not self.leaklookup_api_key:
            raise ValueError("LEAKLOOKUP_ENABLED=true requires LEAKLOOKUP_API_KEY")
        return self

    @property
    def allowed_domains(self) -> tuple[str, ...]:
        return tuple(x.strip().lower().rstrip(".") for x in self.easm_allowed_domains.split(",") if x.strip())

    @property
    def trusted_host_list(self) -> list[str]:
        return [x.strip() for x in self.trusted_hosts.split(",") if x.strip()]

    @property
    def cors_origin_list(self) -> list[str]:
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
