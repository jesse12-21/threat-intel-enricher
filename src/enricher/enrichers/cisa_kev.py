"""CISA KEV enricher — is this CVE actually being exploited?

The Known Exploited Vulnerabilities catalog is CISA's authoritative list of
vulnerabilities with confirmed in-the-wild exploitation. It answers a question
CVSS cannot: not "how bad would this be" but "is anyone actually doing it".

A CVSS 9.8 with no observed exploitation and a CVSS 7.5 on the KEV list are not
the same operational problem, and the second one is usually the more urgent.
KEV entries also carry a federal remediation due date, which makes them useful
for prioritisation even outside government.

The catalog is a single public JSON document — no key, no rate limit. It is
fetched once and cached for the lifetime of the enricher rather than queried
per indicator, because it is roughly 1,500 entries and re-downloading it for
every CVE would be wasteful and slow.

Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
"""
from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, ClassVar

import aiohttp
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from enricher.enrichers.base import BaseEnricher
from enricher.models import IOC, EnrichmentResult, IOCType

logger = logging.getLogger(__name__)

CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)


class CISAKEVEnricher(BaseEnricher):
    """Enricher flagging CVEs present in the CISA KEV catalog."""

    name = "cisa_kev"
    supported_ioc_types: ClassVar[list[IOCType]] = [IOCType.CVE]

    def __init__(self, session: aiohttp.ClientSession) -> None:
        super().__init__(session)
        self._catalog: dict[str, dict[str, Any]] | None = None
        self._lock = asyncio.Lock()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(aiohttp.ClientError),
        reraise=True,
    )
    async def _fetch_catalog(self) -> dict[str, Any]:
        """Download the KEV catalog. Transport errors propagate for retry."""
        async with self.session.get(CATALOG_URL) as response:
            response.raise_for_status()
            payload: dict[str, Any] = await response.json(content_type=None)
            return payload

    async def _load_catalog(self) -> dict[str, dict[str, Any]]:
        """Fetch and index the catalog once, guarded against concurrent loads.

        The lock matters: the pipeline enriches IOCs concurrently, so without
        it a batch of CVEs would each trigger their own download of the same
        1,500-entry document.
        """
        async with self._lock:
            if self._catalog is not None:
                return self._catalog

            payload = await self._fetch_catalog()
            self._catalog = {
                entry["cveID"].upper(): entry
                for entry in payload.get("vulnerabilities", [])
                if entry.get("cveID")
            }
            logger.info("Loaded CISA KEV catalog: %d entries", len(self._catalog))
            return self._catalog

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        if not self.supports(ioc):
            return None

        try:
            catalog = await self._load_catalog()
        except aiohttp.ClientError as e:
            logger.warning("CISA KEV catalog fetch failed after retries: %s", e)
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                error=str(e),
            )

        entry = catalog.get(ioc.value.upper())

        if entry is None:
            # Absence from KEV is not evidence of safety — the catalog covers
            # confirmed exploitation, not all exploitable vulnerabilities.
            return EnrichmentResult(
                ioc=ioc,
                source=self.name,
                malicious=False,
                confidence=0.0,
                categories=["not-in-kev"],
                reference_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            )

        categories = ["known-exploited"]
        if entry.get("knownRansomwareCampaignUse", "").lower() == "known":
            categories.append("ransomware-campaign")

        vendor = entry.get("vendorProject", "")
        product = entry.get("product", "")
        if vendor or product:
            categories.append(f"{vendor} {product}".strip())

        last_seen = None
        date_added = entry.get("dateAdded")
        if date_added:
            try:
                # KEV dateAdded is a bare date. Attaching UTC keeps it
                # comparable with the aware datetimes used elsewhere.
                last_seen = datetime.strptime(date_added, "%Y-%m-%d").replace(
                    tzinfo=UTC
                )
            except ValueError:
                logger.debug("Unparseable KEV dateAdded for %s: %r", ioc.value, date_added)

        # Confidence is 1.0 rather than scaled. KEV membership is a binary,
        # authoritative fact: CISA has confirmed exploitation. There is no
        # partial credit to express.
        return EnrichmentResult(
            ioc=ioc,
            source=self.name,
            malicious=True,
            confidence=1.0,
            categories=categories,
            last_seen=last_seen,
            reference_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            raw_response=entry,
        )
