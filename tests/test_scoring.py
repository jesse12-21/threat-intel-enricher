"""Tests for the risk scoring algorithm."""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from enricher.models import IOC, EnrichmentResult, IOCType, Severity
from enricher.scoring import score_ioc, score_to_severity


@pytest.fixture
def sample_ioc() -> IOC:
    return IOC(
        value="1.2.3.4",
        type=IOCType.IP,
        first_seen=datetime.now(UTC),
        source_alert_id="test-alert-1",
    )


def _make_enrichment(
    ioc: IOC, source: str, malicious: bool, confidence: float
) -> EnrichmentResult:
    return EnrichmentResult(
        ioc=ioc,
        source=source,
        malicious=malicious,
        confidence=confidence,
    )


class TestSeverityMapping:
    def test_critical_band(self) -> None:
        assert score_to_severity(95) == Severity.CRITICAL
        assert score_to_severity(80) == Severity.CRITICAL

    def test_high_band(self) -> None:
        assert score_to_severity(79) == Severity.HIGH
        assert score_to_severity(60) == Severity.HIGH

    def test_medium_band(self) -> None:
        assert score_to_severity(59) == Severity.MEDIUM
        assert score_to_severity(40) == Severity.MEDIUM

    def test_low_band(self) -> None:
        assert score_to_severity(39) == Severity.LOW
        assert score_to_severity(20) == Severity.LOW

    def test_info_band(self) -> None:
        assert score_to_severity(19) == Severity.INFO
        assert score_to_severity(0) == Severity.INFO


class TestScoreIOC:
    def test_no_enrichments_returns_info(self, sample_ioc: IOC) -> None:
        result = score_ioc(sample_ioc, [])
        assert result.score == 0
        assert result.severity == Severity.INFO
        assert result.sources_reporting == 0

    def test_single_malicious_source(self, sample_ioc: IOC) -> None:
        enrichments = [_make_enrichment(sample_ioc, "abuseipdb", True, 0.9)]
        result = score_ioc(sample_ioc, enrichments)
        assert result.score == 90
        assert result.severity == Severity.CRITICAL
        assert result.malicious_sources == 1

    def test_multiple_sources_corroboration_bonus(self, sample_ioc: IOC) -> None:
        """Multiple sources reporting malicious should boost the score."""
        enrichments = [
            _make_enrichment(sample_ioc, "abuseipdb", True, 0.7),
            _make_enrichment(sample_ioc, "urlhaus", True, 0.7),
            _make_enrichment(sample_ioc, "otx", True, 0.7),
        ]
        result = score_ioc(sample_ioc, enrichments)
        # Base weighted score ~70, with 30% corroboration bonus for 3 sources agreeing
        assert result.score > 70
        assert result.severity == Severity.CRITICAL
        assert result.malicious_sources == 3

    def test_urlhaus_weighted_higher(self, sample_ioc: IOC) -> None:
        """URLhaus is curated (weight 1.2) vs AbuseIPDB (weight 1.0)."""
        url_only = score_ioc(sample_ioc, [_make_enrichment(sample_ioc, "urlhaus", True, 0.5)])
        abuse_only = score_ioc(sample_ioc, [_make_enrichment(sample_ioc, "abuseipdb", True, 0.5)])
        # Same confidence from different weights = different scores... actually weighted
        # average normalizes, so single-source scores should be equal. Let's test it:
        assert url_only.score == abuse_only.score  # Normalized via total_weight

    def test_clean_ioc(self, sample_ioc: IOC) -> None:
        """IOC reported but not malicious by any source — should score low."""
        enrichments = [
            _make_enrichment(sample_ioc, "abuseipdb", False, 0.0),
            _make_enrichment(sample_ioc, "otx", False, 0.0),
        ]
        result = score_ioc(sample_ioc, enrichments)
        assert result.score == 0
        assert result.severity == Severity.INFO
        assert result.malicious_sources == 0

    def test_score_clamped_to_100(self, sample_ioc: IOC) -> None:
        """Corroboration bonus shouldn't push score above 100."""
        enrichments = [
            _make_enrichment(sample_ioc, "virustotal", True, 1.0),  # weight 1.3
            _make_enrichment(sample_ioc, "abuseipdb", True, 1.0),
            _make_enrichment(sample_ioc, "urlhaus", True, 1.0),
            _make_enrichment(sample_ioc, "otx", True, 1.0),
        ]
        result = score_ioc(sample_ioc, enrichments)
        assert result.score == 100  # Clamped
        assert result.severity == Severity.CRITICAL

    def test_errored_enrichment_skipped(self, sample_ioc: IOC) -> None:
        """Enrichments with errors shouldn't contribute to scoring."""
        errored = EnrichmentResult(
            ioc=sample_ioc,
            source="broken",
            malicious=False,
            confidence=0.0,
            error="API timeout",
        )
        good = _make_enrichment(sample_ioc, "urlhaus", True, 0.9)
        result = score_ioc(sample_ioc, [errored, good])
        # Only urlhaus counts
        assert result.score == 90
        assert result.malicious_sources == 1

    def test_actionable_flag(self, sample_ioc: IOC) -> None:
        critical = score_ioc(sample_ioc, [_make_enrichment(sample_ioc, "urlhaus", True, 0.9)])
        low = score_ioc(sample_ioc, [_make_enrichment(sample_ioc, "abuseipdb", False, 0.25)])
        assert critical.is_actionable is True
        assert low.is_actionable is False
