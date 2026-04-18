"""URLhaus enricher — malicious URL and domain lookups (no API key required).

URLhaus is a project by abuse.ch that maintains a database of URLs being
used for malware distribution. It's curated and high-precision — matches
are essentially guaranteed to be malicious.

API docs: https://urlhaus-api.abuse.ch/
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher
from enricher.models import EnrichmentResult, IOC, IOCType

logger = logging.getLogger(__name__)

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausEnricher(BaseEnricher):
    """Enricher for malicious URLs and domains via URLhaus."""

    name = "urlhaus"
    supported_ioc_types = [IOCType.URL, IOCType.DOMAIN]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=True,
    )
    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        if ioc.type == IOCType.URL:
            endpoint = URL_ENDPOINT
            form_data = {"url": ioc.value}
        else:  # DOMAIN
            endpoint = HOST_ENDPOINT
            form_data = {"host": ioc.value}

        try:
            async with self.session.post(endpoint, data=form_data) as response:
                response.raise_for_status()
                data = await response.json()
        except aiohttp.ClientError as e:
            logger.warning("URLhaus request failed for %s: %s", ioc.value, e)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error=str(e),
            )

        # URLhaus returns query_status="no_results" for clean/unknown IOCs
        if data.get("query_status") != "ok":
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                categories=[],
                raw_response=data,
            )

        # URLhaus only lists confirmed malicious — any match is high confidence
        return EnrichmentResult(
            ioc=ioc,
            source=self.name,
            malicious=True,
            confidence=1.0,
            categories=_extract_tags(data),
            last_seen=_parse_date(data.get("date_added")),
            reference_url=data.get("urlhaus_reference"),
            raw_response=data,
        )


def _extract_tags(data: dict[str, Any]) -> list[str]:
    """Pull threat tags from a URLhaus response."""
    tags = data.get("tags") or []
    if isinstance(tags, list):
        return [str(t) for t in tags]
    return []


def _parse_date(date_str: str | None) -> datetime | None:
    """Parse URLhaus date format: '2024-03-15 10:23:45 UTC'."""
    if not date_str:
        return None
    try:
        return datetime.strptime(date_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
