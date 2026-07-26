from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.domain import DomainValidationError, normalize_domain


class ScanCreate(BaseModel):
    domain: str = Field(min_length=1, max_length=253)

    @field_validator("domain")
    @classmethod
    def normalize(cls, value: str) -> str:
        try:
            return normalize_domain(value)
        except DomainValidationError as exc:
            raise ValueError(str(exc)) from exc


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target: str
    status: str
    attempts: int
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    summary: dict[str, Any]


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_type: str
    value: str
    sources: list[str]
    details: dict[str, Any]
    created_at: datetime


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str | None
    title: str
    severity: int
    category: str
    source: str
    evidence: dict[str, Any]
    remediation: str
    created_at: datetime


class CollectorRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    collector_name: str
    status: str
    item_count: int
    started_at: datetime
    completed_at: datetime | None
    error: str | None
    metadata_json: dict[str, Any]


class ScanDetailOut(ScanOut):
    assets: list[AssetOut]
    findings: list[FindingOut]
    collector_runs: list[CollectorRunOut]


class RuntimeMeta(BaseModel):
    censys_enabled: bool
    censys_configured: bool
    zoomeye_enabled: bool
    zoomeye_configured: bool
    leaklookup_enabled: bool
    leaklookup_configured: bool
    authorized_scope_count: int
    arbitrary_targets_allowed: bool
