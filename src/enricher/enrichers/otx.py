"""AlienVault OTX enricher — community threat intelligence.

OTX (Open Threat Exchange) is a community-driven threat intel platform.
Analysts publish "pulses" (groups of IOCs from a specific campaign or
investigation) that can be queried for context on specific indicators.

API docs: https://otx.alienvault.com/api
"""
from __future__ import annotations

import logging

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.models import EnrichmentResult, IOC, IOCType

logger = logging.getLogger(__name__)

API_BASE = "https://otx.alienvault.com/api/v1/indicators"


class OTXEnricher(BaseEnricher):
    """Enricher for community threat intel via AlienVault OTX."""

    name = "otx"
    supported_ioc_types = [
        IOCType.IP,
        IOCType.DOMAIN,
        IOCType.URL,
        IOCType.HASH_MD5,
        IOCType.HASH_SHA256,
    ]

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

        url = self._build_url(ioc)
        headers = {"X-OTX-API-KEY": self.api_key}

        try:
            async with self.session.get(url, headers=headers) as response:
                if response.status == 429:
                    raise RateLimitError(f"OTX rate limit hit for {ioc.value}")
                if response.status == 401:
                    raise EnrichmentError("OTX API key is invalid")
                if response.status == 404:
                    # No pulses for this IOC — not necessarily clean, just no data
                    return EnrichmentResult(
                        ioc=ioc,
                        source=self.name,
                        malicious=False,
                        confidence=0.0,
                    )
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError as e:
            logger.warning("OTX request failed for %s: %s", ioc.value, e)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error=str(e),
            )

        pulse_info = data.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)

        # More pulses = more community reports = higher confidence of maliciousness
        # Scale: 1 pulse -> 0.3, 5 pulses -> 0.7, 10+ pulses -> 1.0
        confidence = min(1.0, pulse_count * 0.1 + 0.2) if pulse_count > 0 else 0.0

        categories = []
        for pulse in pulse_info.get("pulses", [])[:5]:
            if isinstance(pulse, dict) and "tags" in pulse:
                categories.extend(pulse["tags"][:3])

        return EnrichmentResult(
            ioc=ioc,
            source=self.name,
            malicious=pulse_count > 0,
            confidence=confidence,
            categories=list(set(categories))[:10],
            reference_url=f"https://otx.alienvault.com/indicator/{ioc.type.value}/{ioc.value}",
            raw_response={"pulse_count": pulse_count, "pulse_info": pulse_info},
        )

    @staticmethod
    def _build_url(ioc: IOC) -> str:
        """Build the OTX API URL for this IOC type."""
        endpoints = {
            IOCType.IP: f"{API_BASE}/IPv4/{ioc.value}/general",
            IOCType.DOMAIN: f"{API_BASE}/domain/{ioc.value}/general",
            IOCType.URL: f"{API_BASE}/url/{ioc.value}/general",
            IOCType.HASH_MD5: f"{API_BASE}/file/{ioc.value}/general",
            IOCType.HASH_SHA256: f"{API_BASE}/file/{ioc.value}/general",
        }
        return endpoints[ioc.type]
