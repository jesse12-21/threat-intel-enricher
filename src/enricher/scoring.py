"""Weighted multi-source risk scoring for enriched IOCs.

A single threat intel source reporting an IOC as malicious is useful.
Multiple sources agreeing is much more compelling. This module implements
a weighted scoring algorithm that rewards corroboration across sources.
"""
from __future__ import annotations

from enricher.models import EnrichmentResult, IOC, RiskScore, Severity


# Source weights reflect data quality and precision:
#   - Curated sources (URLhaus) score slightly higher than crowd-sourced
#   - Aggregators (VirusTotal) get the highest weight as meta-sources
#   - Community feeds (AbuseIPDB, OTX) form the baseline
SOURCE_WEIGHTS: dict[str, float] = {
    "abuseipdb": 1.0,
    "urlhaus": 1.2,
    "otx": 1.0,
    "virustotal": 1.3,
}

# Severity bands mapping score → severity label
SEVERITY_THRESHOLDS: list[tuple[int, Severity]] = [
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
    (0, Severity.INFO),
]


def score_to_severity(score: int) -> Severity:
    """Map a numeric score (0-100) to a severity band."""
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def score_ioc(ioc: IOC, enrichments: list[EnrichmentResult]) -> RiskScore:
    """Calculate a weighted risk score for an IOC across all enrichment sources.

    Algorithm:
        1. Compute weighted average of confidence scores across sources
        2. Apply a corroboration multiplier when multiple sources agree
        3. Clamp final score to 0-100 and map to severity band

    Args:
        ioc: The indicator being scored
        enrichments: Results from all queried threat intel sources

    Returns:
        RiskScore with final score, severity, and supporting enrichment data
    """
    if not enrichments:
        return RiskScore(
            ioc=ioc,
            score=0,
            severity=Severity.INFO,
            sources_reporting=0,
            malicious_sources=0,
            enrichments=[],
        )

    # Calculate weighted average of confidence scores
    weighted_sum = 0.0
    total_weight = 0.0
    malicious_count = 0

    for result in enrichments:
        if result.error:
            continue  # Skip errored enrichments

        weight = SOURCE_WEIGHTS.get(result.source, 1.0)
        weighted_sum += result.confidence * weight * 100
        total_weight += weight

        if result.malicious:
            malicious_count += 1

    base_score = weighted_sum / total_weight if total_weight > 0 else 0.0

    # Corroboration bonus: 15% boost per additional source that agrees
    if malicious_count > 1:
        corroboration_multiplier = 1.0 + (0.15 * (malicious_count - 1))
        base_score *= corroboration_multiplier

    final_score = min(100, max(0, int(round(base_score))))

    return RiskScore(
        ioc=ioc,
        score=final_score,
        severity=score_to_severity(final_score),
        sources_reporting=len([e for e in enrichments if not e.error]),
        malicious_sources=malicious_count,
        enrichments=enrichments,
    )


def score_many(
    enrichments_by_ioc: dict[IOC, list[EnrichmentResult]]
) -> list[RiskScore]:
    """Score multiple IOCs and return sorted by score (highest first)."""
    scores = [score_ioc(ioc, results) for ioc, results in enrichments_by_ioc.items()]
    return sorted(scores, key=lambda s: s.score, reverse=True)
