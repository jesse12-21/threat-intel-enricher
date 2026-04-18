"""Pipeline orchestration — glue all stages together with concurrent execution.

The pipeline runs the full workflow: ingest alerts, extract IOCs, concurrently
enrich against all configured sources, score results, and correlate campaigns.
"""
from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.models import Alert, EnrichmentResult, IOC, RiskScore

logger = logging.getLogger(__name__)


async def enrich_ioc(
    ioc: IOC,
    enrichers: list[BaseEnricher],
    semaphore: asyncio.Semaphore,
) -> list[EnrichmentResult]:
    """Query all applicable enrichers for a single IOC, concurrently.

    Uses a semaphore to limit global concurrency across all IOCs, preventing
    API rate limits and resource exhaustion.
    """
    applicable = [e for e in enrichers if e.supports(ioc)]
    if not applicable:
        return []

    async def _bounded_enrich(enricher: BaseEnricher) -> EnrichmentResult | None:
        async with semaphore:
            try:
                return await enricher.enrich(ioc)
            except RateLimitError as e:
                logger.warning("Rate limit: %s", e)
                return None
            except EnrichmentError as e:
                logger.error("Enrichment failed for %s on %s: %s", ioc.value, enricher.name, e)
                return None

    results = await asyncio.gather(*[_bounded_enrich(e) for e in applicable])
    return [r for r in results if r is not None]


async def enrich_all_iocs(
    iocs: list[IOC],
    enrichers: list[BaseEnricher],
    max_concurrent: int = 10,
) -> dict[IOC, list[EnrichmentResult]]:
    """Enrich a batch of IOCs concurrently.

    Deduplicates IOCs by value+type before enrichment to avoid redundant API
    calls for the same indicator appearing across multiple alerts.
    """
    semaphore = asyncio.Semaphore(max_concurrent)

    # Deduplicate IOCs — they're hashable by (value, type)
    unique_iocs = list(set(iocs))
    logger.info("Enriching %d unique IOCs (from %d total)", len(unique_iocs), len(iocs))

    tasks = [enrich_ioc(ioc, enrichers, semaphore) for ioc in unique_iocs]
    results = await asyncio.gather(*tasks)

    return dict(zip(unique_iocs, results, strict=True))


def group_iocs_by_alert(
    alerts: list[Alert],
    ioc_scores: list[RiskScore],
) -> dict[str, list[RiskScore]]:
    """Map alert IDs to the risk scores of their associated IOCs."""
    by_alert: dict[str, list[RiskScore]] = defaultdict(list)
    for score in ioc_scores:
        by_alert[score.ioc.source_alert_id].append(score)
    return dict(by_alert)
