"""AbuseIPDB enricher — IP reputation lookups.

AbuseIPDB aggregates IP abuse reports from the global security community.
Free tier: 1,000 checks per day.

API docs: https://docs.abuseipdb.com/
"""
from __future__ import annotations

import logging
from typing import Any, ClassVar

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.models import IOC, EnrichmentResult, IOCType

logger = logging.getLogger(__name__)

API_URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_THRESHOLD = 25  # Confidence score above which we flag as malicious


class AbuseIPDBEnricher(BaseEnricher):
    """Enricher for IP reputation via AbuseIPDB."""

    name = "abuseipdb"
    supported_ioc_types: ClassVar[list[IOCType]] = [IOCType.IP]

    def __init__(self, session: aiohttp.ClientSession, api_key: str) -> None:
        super().__init__(session)
        self.api_key = api_key

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=True,
    )
    async def _fetch(self, ioc: IOC) -> dict[str, Any]:
        """Perform the HTTP request, letting transport errors propagate.

        The retry decorator belongs here rather than on enrich(). An earlier
        version decorated enrich() while catching aiohttp.ClientError inside
        it, so the exception never escaped for tenacity to observe and the
        retry never fired — one attempt was made, not three. Splitting the
        request out means transport failures propagate through the retry
        logic, and enrich() only sees an error once all attempts are spent.
        """
        headers = {
            "Key": self.api_key,
            "Accept": "application/json",
        }
        params = {
            "ipAddress": ioc.value,
            "maxAgeInDays": "90",
            "verbose": "true",
        }

        async with self.session.get(API_URL, headers=headers, params=params) as response:
            if response.status == 429:
                raise RateLimitError(f"AbuseIPDB rate limit hit for {ioc.value}")
            if response.status == 401:
                raise EnrichmentError("AbuseIPDB API key is invalid")
            response.raise_for_status()
            payload: dict[str, Any] = await response.json()
            return payload

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        try:
            payload = await self._fetch(ioc)
        except aiohttp.ClientError as e:
            logger.warning("AbuseIPDB request failed for %s after retries: %s", ioc.value, e)
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
