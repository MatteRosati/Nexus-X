from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CollectorResult:
    name: str
    assets: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
