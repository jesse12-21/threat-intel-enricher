"""Tests for all enrichers.

Two of these are regression tests for bugs that shipped and survived because
this file did not exist:

  * test_retry_actually_fires_on_transport_error — the @retry decorator was
    attached to enrich() while enrich() caught aiohttp.ClientError internally,
    so the exception never escaped for tenacity to observe. One attempt was
    made where three were configured.

  * test_urlhaus_sends_auth_key — abuse.ch made the Auth-Key header mandatory
    on 2025-06-30. The enricher sent no headers at all and had been returning
    401 on every call since.
"""
from __future__ import annotations

import aiohttp
import pytest

from enricher.enrichers import (
    AbuseIPDBEnricher,
    CISAKEVEnricher,
    EPSSEnricher,
    OTXEnricher,
    URLhausEnricher,
)
from enricher.enrichers.base import EnrichmentError, RateLimitError
from enricher.models import IOC, IOCType

from .conftest import FakeResponse, FakeSession

# --------------------------------------------------------------------------
# Regression: retry
# --------------------------------------------------------------------------


async def test_retry_actually_fires_on_transport_error(ip_ioc: IOC) -> None:
    """The retry decorator must make three attempts, not one.

    Regression test. The decorator sat on enrich() while enrich() swallowed
    aiohttp.ClientError, so tenacity never saw a retryable exception.
    """
    session = FakeSession(aiohttp.ClientError("simulated network failure"))
    enricher = AbuseIPDBEnricher(session, "test-key")  # type: ignore[arg-type]

    result = await enricher.enrich(ip_ioc)

    assert session.call_count == 3, (
        f"expected 3 attempts from stop_after_attempt(3), got {session.call_count}"
    )
    assert result is not None
    assert result.error is not None
    assert result.malicious is False


async def test_retry_gives_up_and_returns_error_result(ip_ioc: IOC) -> None:
    """After retries are exhausted the caller gets a result, not an exception."""
    session = FakeSession(aiohttp.ClientError("down"))
    enricher = AbuseIPDBEnricher(session, "k")  # type: ignore[arg-type]

    result = await enricher.enrich(ip_ioc)

    assert result is not None
    assert result.source == "abuseipdb"
    assert result.confidence == 0.0


async def test_no_retry_on_success(ip_ioc: IOC) -> None:
    """A successful call must not be repeated."""
    session = FakeSession(FakeResponse(payload={"data": {"abuseConfidenceScore": 10}}))
    enricher = AbuseIPDBEnricher(session, "k")  # type: ignore[arg-type]

    await enricher.enrich(ip_ioc)

    assert session.call_count == 1


# --------------------------------------------------------------------------
# Regression: URLhaus authentication
# --------------------------------------------------------------------------


async def test_urlhaus_sends_auth_key(url_ioc: IOC) -> None:
    """abuse.ch requires the Auth-Key header; without it every call 401s.

    Regression test for an enricher that sent no headers at all.
    """
    session = FakeSession(FakeResponse(payload={"query_status": "no_results"}))
    enricher = URLhausEnricher(session, "abusech-key")  # type: ignore[arg-type]

    await enricher.enrich(url_ioc)

    assert session.last_headers.get("Auth-Key") == "abusech-key"


async def test_urlhaus_401_raises_actionable_error(url_ioc: IOC) -> None:
    """A rejected key must say what to do about it, not fail opaquely."""
    session = FakeSession(FakeResponse(status=401))
    enricher = URLhausEnricher(session, "bad-key")  # type: ignore[arg-type]

    with pytest.raises(EnrichmentError, match="auth.abuse.ch"):
        await enricher.enrich(url_ioc)


async def test_urlhaus_uses_correct_endpoint_per_ioc_type(
    url_ioc: IOC, domain_ioc: IOC
) -> None:
    session = FakeSession(FakeResponse(payload={"query_status": "no_results"}))
    enricher = URLhausEnricher(session, "k")  # type: ignore[arg-type]

    await enricher.enrich(url_ioc)
    assert session.calls[-1]["url"].endswith("/url/")

    await enricher.enrich(domain_ioc)
    assert session.calls[-1]["url"].endswith("/host/")


# --------------------------------------------------------------------------
# AbuseIPDB
# --------------------------------------------------------------------------


async def test_abuseipdb_flags_malicious_above_threshold(ip_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(payload={"data": {"abuseConfidenceScore": 90}}))
    result = await AbuseIPDBEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is True
    assert result.confidence == pytest.approx(0.9)


async def test_abuseipdb_clean_below_threshold(ip_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(payload={"data": {"abuseConfidenceScore": 5}}))
    result = await AbuseIPDBEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is False


async def test_abuseipdb_rate_limit_raises(ip_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(status=429))
    with pytest.raises(RateLimitError):
        await AbuseIPDBEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]


async def test_abuseipdb_invalid_key_raises(ip_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(status=401))
    with pytest.raises(EnrichmentError, match="invalid"):
        await AbuseIPDBEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]


async def test_enricher_returns_none_for_unsupported_type(url_ioc: IOC) -> None:
    """AbuseIPDB handles IPs only; a URL must short-circuit without a request."""
    session = FakeSession(FakeResponse())
    result = await AbuseIPDBEnricher(session, "k").enrich(url_ioc)  # type: ignore[arg-type]

    assert result is None
    assert session.call_count == 0, "unsupported IOC types must not consume API quota"


# --------------------------------------------------------------------------
# OTX
# --------------------------------------------------------------------------


async def test_otx_404_is_no_data_not_an_error(ip_ioc: IOC) -> None:
    """OTX returns 404 for indicators with no pulses. That is an absence of
    data, not a failure, and it is not evidence the indicator is clean."""
    session = FakeSession(FakeResponse(status=404))
    result = await OTXEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.error is None
    assert result.malicious is False
    assert result.confidence == 0.0


async def test_otx_confidence_scales_with_pulse_count(ip_ioc: IOC) -> None:
    session = FakeSession(
        FakeResponse(payload={"pulse_info": {"count": 5, "pulses": [{"tags": ["emotet"]}]}})
    )
    result = await OTXEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is True
    assert result.confidence == pytest.approx(0.7)
    assert "emotet" in result.categories


async def test_otx_confidence_caps_at_one(ip_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(payload={"pulse_info": {"count": 500, "pulses": []}}))
    result = await OTXEnricher(session, "k").enrich(ip_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.confidence == 1.0


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------

KEV_PAYLOAD = {
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "dateAdded": "2021-12-10",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2020-0001",
            "vendorProject": "Example",
            "product": "Thing",
            "dateAdded": "2020-01-01",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ]
}


async def test_kev_flags_listed_cve(cve_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(payload=KEV_PAYLOAD))
    result = await CISAKEVEnricher(session).enrich(cve_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is True
    assert result.confidence == 1.0
    assert "known-exploited" in result.categories
    assert "ransomware-campaign" in result.categories


async def test_kev_absence_is_not_evidence_of_safety(fixed_time: object) -> None:
    session = FakeSession(FakeResponse(payload=KEV_PAYLOAD))
    ioc = IOC(
        value="CVE-1999-0001",
        type=IOCType.CVE,
        first_seen=fixed_time,  # type: ignore[arg-type]
        source_alert_id="a",
    )
    result = await CISAKEVEnricher(session).enrich(ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is False
    assert "not-in-kev" in result.categories


async def test_kev_catalog_fetched_once_across_many_cves(cve_ioc: IOC, fixed_time: object) -> None:
    """The catalog is ~1,500 entries. Downloading it per indicator would be
    wasteful, so it is cached behind a lock."""
    session = FakeSession(FakeResponse(payload=KEV_PAYLOAD))
    enricher = CISAKEVEnricher(session)  # type: ignore[arg-type]

    for n in range(5):
        ioc = IOC(
            value=f"CVE-2021-4422{n}",
            type=IOCType.CVE,
            first_seen=fixed_time,  # type: ignore[arg-type]
            source_alert_id="a",
        )
        await enricher.enrich(ioc)

    assert session.call_count == 1


async def test_kev_cve_matching_is_case_insensitive(fixed_time: object) -> None:
    session = FakeSession(FakeResponse(payload=KEV_PAYLOAD))
    ioc = IOC(
        value="cve-2021-44228",
        type=IOCType.CVE,
        first_seen=fixed_time,  # type: ignore[arg-type]
        source_alert_id="a",
    )
    result = await CISAKEVEnricher(session).enrich(ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is True


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------


async def test_epss_high_probability_flagged(cve_ioc: IOC) -> None:
    session = FakeSession(
        FakeResponse(payload={"data": [{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99"}]})
    )
    result = await EPSSEnricher(session).enrich(cve_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is True
    assert result.confidence == pytest.approx(0.97)
    assert "high-exploitation-probability" in result.categories


async def test_epss_low_probability_not_flagged(cve_ioc: IOC) -> None:
    session = FakeSession(
        FakeResponse(payload={"data": [{"cve": "CVE-2021-44228", "epss": "0.0004", "percentile": "0.05"}]})
    )
    result = await EPSSEnricher(session).enrich(cve_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.malicious is False


async def test_epss_missing_score_is_not_low_risk(cve_ioc: IOC) -> None:
    """An unscored CVE is usually too new to have been scored, which is not
    the same as being low risk."""
    session = FakeSession(FakeResponse(payload={"data": []}))
    result = await EPSSEnricher(session).enrich(cve_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert "no-epss-score" in result.categories
    assert result.error is None


async def test_epss_handles_unparseable_score(cve_ioc: IOC) -> None:
    session = FakeSession(FakeResponse(payload={"data": [{"epss": "not-a-number"}]}))
    result = await EPSSEnricher(session).enrich(cve_ioc)  # type: ignore[arg-type]

    assert result is not None
    assert result.error is not None
