"""EPSS enricher — how likely is this CVE to be exploited?

The Exploit Prediction Scoring System, maintained by FIRST, estimates the
probability that a vulnerability will be exploited in the wild within the next
30 days. It is a different question from CVSS, which measures severity if
exploited, and from KEV, which records confirmed past exploitation.

The three answer different things and are most useful together:

    CVSS   how bad would it be        severity
    KEV    has it happened            confirmed fact
    EPSS   will it happen soon        forecast

The practical value is triage. A CVSS 9.8 with an EPSS score of 0.0004 and a
CVSS 7.5 with an EPSS of 0.87 will be ranked identically by severity alone,
and the second is far more likely to be used against you this month.

Public API, no key, no documented rate limit.

API docs: https://www.first.org/epss/api
"""
from __future__ import annotations

import logging
from typing import Any, ClassVar

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher
from enricher.models import IOC, EnrichmentResult, IOCType

logger = logging.getLogger(__name__)

API_URL = "https://api.first.org/data/v1/epss"

# EPSS probabilities are heavily skewed — the median CVE scores well under
# 0.01. A score above 0.10 puts a vulnerability in roughly the top few percent
# by predicted exploitation, which is the point at which it is worth treating
# as an active concern rather than a backlog item.
MALICIOUS_THRESHOLD = 0.10


class EPSSEnricher(BaseEnricher):
    """Enricher providing exploitation probability for CVEs via FIRST EPSS."""

    name = "epss"
    supported_ioc_types: ClassVar[list[IOCType]] = [IOCType.CVE]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=True,
    )
    async def _fetch(self, ioc: IOC) -> dict[str, Any]:
        """Perform the HTTP request, letting transport errors propagate."""
        params = {"cve": ioc.value.upper()}
        async with self.session.get(API_URL, params=params) as response:
            response.raise_for_status()
            payload: dict[str, Any] = await response.json(content_type=None)
            return payload

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        try:
            payload = await self._fetch(ioc)
        except aiohttp.ClientError as e:
            logger.warning("EPSS request failed for %s after retries: %s", ioc.value, e)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error=str(e),
            )

        records = payload.get("data", [])
        if not records:
            # EPSS only covers published CVEs. A miss usually means the CVE is
            # too new to have been scored, not that it is low risk.
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                categories=["no-epss-score"],
                reference_url=f"https://api.first.org/data/v1/epss?cve={ioc.value.upper()}",
            )

        record = records[0]
        try:
            epss = float(record.get("epss", 0.0))
            percentile = float(record.get("percentile", 0.0))
        except (TypeError, ValueError):
            logger.warning("EPSS returned unparseable score for %s: %r", ioc.value, record)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error="unparseable EPSS score",
            )

        categories = [f"epss-percentile-{int(percentile * 100)}"]
        if epss >= 0.5:
            categories.append("high-exploitation-probability")
        elif epss >= MALICIOUS_THRESHOLD:
            categories.append("elevated-exploitation-probability")

        # The EPSS probability maps directly onto confidence: both are 0-1
        # estimates of the same underlying question.
        return EnrichmentResult(
            ioc=ioc,
            source=self.name,
            malicious=epss >= MALICIOUS_THRESHOLD,
            confidence=min(1.0, max(0.0, epss)),
            categories=categories,
            reference_url=f"https://api.first.org/data/v1/epss?cve={ioc.value.upper()}",
            raw_response=record,
        )
