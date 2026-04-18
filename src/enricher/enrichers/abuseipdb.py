"""AbuseIPDB enricher — IP reputation lookups.

AbuseIPDB aggregates IP abuse reports from the global security community.
Free tier: 1,000 checks per day.

API docs: https://docs.abuseipdb.com/
"""
from __future__ import annotations

import logging

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.models import EnrichmentResult, IOC, IOCType

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_THRESHOLD = 25  # Confidence score above which we flag as malicious


class AbuseIPDBEnricher(BaseEnricher):
    """Enricher for IP reputation via AbuseIPDB."""

    name = "abuseipdb"
    supported_ioc_types = [IOCType.IP]

    def __init__(self, session: aiohttp.ClientSession, api_key: str) -> None:
        super().__init__(session)
        self.api_key = api_key

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=True,
    )
    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ioc.value,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        try:
            async with self.session.get(API_URL, headers=headers, params=params) as response:
                if response.status == 429:
                    raise RateLimitError(f"AbuseIPDB rate limit hit for {ioc.value}")
                if response.status == 401:
                    raise EnrichmentError("AbuseIPDB API key is invalid")
                response.raise_for_status()
                payload = await response.json()
        except aiohttp.ClientError as e:
            logger.warning("AbuseIPDB request failed for %s: %s", ioc.value, e)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error=str(e),
            )

        data = payload.get("data", {})
        confidence_score = data.get("abuseConfidenceScore", 0)

        return EnrichmentResult(
            ioc=ioc,
            source=self.name,
            malicious=confidence_score >= MALICIOUS_THRESHOLD,
            confidence=min(1.0, confidence_score / 100.0),
            categories=[
                str(cat) for cat in data.get("reports", [])[:5]
            ],
            reference_url=f"https://www.abuseipdb.com/check/{ioc.value}",
            raw_response=data,
        )
