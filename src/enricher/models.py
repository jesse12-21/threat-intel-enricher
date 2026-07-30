"""Pydantic data models for the threat intelligence enrichment pipeline.

All data flowing through the pipeline is validated with Pydantic, catching
schema errors at boundaries rather than deep in processing logic.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class IOCType(str, Enum):
    """Types of Indicators of Compromise the toolkit processes."""

    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "md5"
    HASH_SHA256 = "sha256"
    CVE = "cve"


class Severity(str, Enum):
    """Risk severity bands for scored IOCs."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IOC(BaseModel):
    """An Indicator of Compromise extracted from an alert."""

    model_config = ConfigDict(frozen=True)

    value: str = Field(..., min_length=1, description="The IOC value (IP, domain, hash, etc.)")
    type: IOCType
    first_seen: datetime
    source_alert_id: str = Field(..., description="ID of the alert this IOC came from")

    def __hash__(self) -> int:
        return hash((self.value, self.type))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, IOC):
            return NotImplemented
        return self.value == other.value and self.type == other.type


class Alert(BaseModel):
    """A normalized alert from any supported IDS source."""

    id: str
    timestamp: datetime
    signature: str
    severity: int = Field(..., ge=1, le=3, description="1=high, 2=medium, 3=low")
    category: str
    src_ip: str
    dest_ip: str
    src_port: int | None = None
    dest_port: int | None = None
    protocol: str | None = None
    dns_query: str | None = None
    http_hostname: str | None = None
    http_url: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class EnrichmentResult(BaseModel):
    """Standardized output from any threat intelligence source."""

    ioc: IOC
    source: str = Field(..., description="Name of the enrichment source (e.g. 'abuseipdb')")
    malicious: bool
    confidence: float = Field(..., ge=0.0, le=1.0)
    categories: list[str] = Field(default_factory=list)
    last_seen: datetime | None = None
    reference_url: str | None = None
    raw_response: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


class RiskScore(BaseModel):
    """Aggregated risk score for an IOC across all enrichment sources."""

    ioc: IOC
    score: int = Field(..., ge=0, le=100)
    severity: Severity
    sources_reporting: int = Field(..., ge=0)
    malicious_sources: int = Field(..., ge=0)
    enrichments: list[EnrichmentResult] = Field(default_factory=list)

    @property
    def is_actionable(self) -> bool:
        """IOCs at medium+ severity warrant analyst attention."""
        return self.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)


class AttackCampaign(BaseModel):
    """A cluster of related alerts indicating a coordinated attack."""

    attacker_ip: str
    start_time: datetime
    end_time: datetime
    alert_count: int
    signatures: list[str]
    alerts: list[Alert]
    top_signature: str | None = None

    @property
    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()
