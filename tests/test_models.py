"""Tests for Pydantic data model validation."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from enricher.models import (
    IOC,
    Alert,
    AttackCampaign,
    EnrichmentResult,
    IOCType,
    RiskScore,
    Severity,
)


class TestIOC:
    def test_valid_ioc(self) -> None:
        ioc = IOC(
            value="8.8.8.8",
            type=IOCType.IP,
            first_seen=datetime.now(UTC),
            source_alert_id="alert-1",
        )
        assert ioc.value == "8.8.8.8"
        assert ioc.type == IOCType.IP

    def test_empty_value_rejected(self) -> None:
        with pytest.raises(ValidationError):
            IOC(
                value="",
                type=IOCType.IP,
                first_seen=datetime.now(UTC),
                source_alert_id="alert-1",
            )

    def test_ioc_is_hashable(self) -> None:
        """IOCs must be hashable for use as dict keys and in sets."""
        now = datetime.now(UTC)
        a = IOC(value="1.2.3.4", type=IOCType.IP, first_seen=now, source_alert_id="a")
        b = IOC(value="1.2.3.4", type=IOCType.IP, first_seen=now, source_alert_id="b")
        # Same value+type → same hash (dedup works)
        assert hash(a) == hash(b)

    def test_dedup_by_value_type(self) -> None:
        """Different IOC instances with same value+type collapse in a set."""
        now = datetime.now(UTC)
        iocs = {
            IOC(value="1.1.1.1", type=IOCType.IP, first_seen=now, source_alert_id="a"),
            IOC(value="1.1.1.1", type=IOCType.IP, first_seen=now, source_alert_id="b"),
            IOC(value="1.1.1.1", type=IOCType.DOMAIN, first_seen=now, source_alert_id="c"),
        }
        # IP and DOMAIN are different types, but two IPs should dedup
        assert len(iocs) == 2


class TestAlert:
    def test_valid_alert(self) -> None:
        alert = Alert(
            id="test-1",
            timestamp=datetime.now(UTC),
            signature="ET MALWARE Test",
            severity=1,
            category="Malware",
            src_ip="1.2.3.4",
            dest_ip="10.0.0.5",
        )
        assert alert.severity == 1

    def test_severity_out_of_range(self) -> None:
        with pytest.raises(ValidationError):
            Alert(
                id="test-1",
                timestamp=datetime.now(UTC),
                signature="Test",
                severity=5,  # Out of range 1-3
                category="Test",
                src_ip="1.2.3.4",
                dest_ip="1.2.3.5",
            )


class TestEnrichmentResult:
    def test_confidence_range(self) -> None:
        ioc = IOC(
            value="1.2.3.4",
            type=IOCType.IP,
            first_seen=datetime.now(UTC),
            source_alert_id="a",
        )
        # Valid
        EnrichmentResult(ioc=ioc, source="test", malicious=True, confidence=0.5)
        EnrichmentResult(ioc=ioc, source="test", malicious=False, confidence=0.0)
        EnrichmentResult(ioc=ioc, source="test", malicious=True, confidence=1.0)

        # Invalid
        with pytest.raises(ValidationError):
            EnrichmentResult(ioc=ioc, source="test", malicious=True, confidence=1.5)
        with pytest.raises(ValidationError):
            EnrichmentResult(ioc=ioc, source="test", malicious=True, confidence=-0.1)


class TestRiskScore:
    def test_is_actionable(self) -> None:
        ioc = IOC(
            value="1.2.3.4",
            type=IOCType.IP,
            first_seen=datetime.now(UTC),
            source_alert_id="a",
        )
        high_score = RiskScore(
            ioc=ioc, score=85, severity=Severity.CRITICAL, sources_reporting=3, malicious_sources=3
        )
        low_score = RiskScore(
            ioc=ioc, score=15, severity=Severity.INFO, sources_reporting=1, malicious_sources=0
        )
        assert high_score.is_actionable is True
        assert low_score.is_actionable is False


class TestAttackCampaign:
    def test_duration_calculation(self) -> None:
        start = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        end = datetime(2026, 1, 1, 12, 5, 30, tzinfo=UTC)
        campaign = AttackCampaign(
            attacker_ip="1.2.3.4",
            start_time=start,
            end_time=end,
            alert_count=10,
            signatures=["Test Signature"],
            alerts=[],
            top_signature="Test Signature",
        )
        assert campaign.duration_seconds == 330.0
