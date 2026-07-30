"""URLhaus enricher — malicious URL and domain lookups.

URLhaus is a project by abuse.ch maintaining a database of URLs used for
malware distribution. It is curated and high-precision, so a match is
strong evidence rather than a weak signal — which is why it carries the
highest source weight in scoring.

AUTHENTICATION IS REQUIRED. abuse.ch made the Auth-Key header mandatory on
30 June 2025 across URLhaus, ThreatFox, and MalwareBazaar; unauthenticated
requests are rejected. An earlier version of this enricher sent no headers
at all and had been returning 401 on every call since that date. The key is
free — obtain one at https://auth.abuse.ch/ — and the same key works for
all three abuse.ch services.

API docs: https://urlhaus-api.abuse.ch/
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.models import IOC, EnrichmentResult, IOCType

logger = logging.getLogger(__name__)

URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"


class URLhausEnricher(BaseEnricher):
    """Enricher for malicious URLs and domains via URLhaus."""

    name = "urlhaus"
    supported_ioc_types: ClassVar[list[IOCType]] = [IOCType.URL, IOCType.DOMAIN]

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

        The retry decorator sits here rather than on enrich() so that
        tenacity can observe aiohttp.ClientError. Decorating enrich() while
        catching that error inside it meant the retry never fired.
        """
        if ioc.type == IOCType.URL:
            endpoint = URL_ENDPOINT
            form_data = {"url": ioc.value}
        else:  # DOMAIN
            endpoint = HOST_ENDPOINT
            form_data = {"host": ioc.value}

        headers = {"Auth-Key": self.api_key}

        async with self.session.post(endpoint, data=form_data, headers=headers) as response:
            if response.status == 429:
                raise RateLimitError(f"URLhaus rate limit hit for {ioc.value}")
            if response.status in (401, 403):
                raise EnrichmentError(
                    "URLhaus rejected the Auth-Key. abuse.ch requires authentication "
                    "since 2025-06-30; get a free key at https://auth.abuse.ch/"
                )
            response.raise_for_status()
            data: dict[str, Any] = await response.json()
            return data

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        try:
            data = await self._fetch(ioc)
        except aiohttp.ClientError as e:
            logger.warning("URLhaus request failed for %s after retries: %s", ioc.value, e)
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
        # URLhaus states these timestamps are UTC. Attaching the tzinfo keeps
        # them comparable with the aware datetimes used elsewhere in the models;
        # a naive datetime here compares wrong rather than raising.
        return datetime.strptime(date_str.replace(" UTC", ""), "%Y-%m-%d %H:%M:%S").replace(
            tzinfo=UTC
        )
    except ValueError:
        return None
