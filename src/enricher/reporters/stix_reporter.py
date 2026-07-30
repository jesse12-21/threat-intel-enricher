"""STIX 2.1 reporter — export scored IOCs as a shareable intelligence bundle.

Markdown and HTML reports are for humans. STIX is for machines: it is the
OASIS standard for threat intelligence interchange, and it is what MISP,
OpenCTI, Anomali, and every commercial TIP consume.

Without it, enrichment output is a dead end — an analyst reads the report and
retypes the indicators somewhere else. With it, the pipeline's output is
directly importable into the tooling the rest of an organisation uses.

This produces a STIX 2.1 bundle containing:

    identity          the tool that produced the bundle
    indicator         one per scored IOC, with a STIX pattern
    note              the enrichment evidence behind each score

Scope, stated honestly: this emits STIX and does not consume it, and it does
not implement TAXII. A TAXII server is a hosting concern rather than a
serialisation one, and the bundles here can be pushed to an existing TAXII
endpoint or imported directly. Bundles are generated without the `stix2`
library so the project keeps its dependency footprint small; the tradeoff is
that structural conformance is asserted by tests rather than by a validator.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from enricher.models import AttackCampaign, IOCType, RiskScore, Severity
from enricher.reporters.base import BaseReporter

# Deterministic namespace so the same tool identity is stable across runs.
# STIX consumers deduplicate on ID, and a fresh UUID each run would create a
# new "producer" identity every time the pipeline executed.
_NAMESPACE = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
TOOL_IDENTITY_ID = f"identity--{uuid.uuid5(_NAMESPACE, 'threat-intel-enricher')}"

# STIX pattern syntax differs per observable type.
_PATTERN_BUILDERS: dict[IOCType, str] = {
    IOCType.IP: "[ipv4-addr:value = '{value}']",
    IOCType.DOMAIN: "[domain-name:value = '{value}']",
    IOCType.URL: "[url:value = '{value}']",
    IOCType.HASH_MD5: "[file:hashes.'MD5' = '{value}']",
    IOCType.HASH_SHA256: "[file:hashes.'SHA-256' = '{value}']",
    IOCType.CVE: "[vulnerability:name = '{value}']",
}

# STIX has no numeric severity field, so severity maps onto the confidence
# property, which STIX 2.1 defines as a 0-100 integer.
_CONFIDENCE_BY_SEVERITY: dict[Severity, int] = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 80,
    Severity.MEDIUM: 60,
    Severity.LOW: 30,
    Severity.INFO: 10,
}


def _now() -> str:
    """STIX timestamps are RFC 3339 with millisecond precision and a Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _escape(value: str) -> str:
    """Escape a value for embedding in a STIX pattern string literal.

    Backslashes must be escaped before quotes, or the escaping of quotes is
    itself re-escaped. Matters for URL indicators, which routinely contain both.
    """
    return value.replace("\\", "\\\\").replace("'", "\\'")


def build_pattern(ioc_type: IOCType, value: str) -> str | None:
    """Build a STIX pattern for an IOC, or None if the type has no mapping."""
    template = _PATTERN_BUILDERS.get(ioc_type)
    if template is None:
        return None
    return template.format(value=_escape(value))


def build_bundle(scores: list[RiskScore], *, actionable_only: bool = True) -> dict[str, Any]:
    """Build a STIX 2.1 bundle from scored IOCs.

    Args:
        scores: Risk scores to export.
        actionable_only: Export only medium severity and above. Defaults to
            True because a bundle full of INFO-severity indicators is worse
            than useless in a TIP — it dilutes the feed and trains analysts
            to ignore it.

    Returns:
        A STIX 2.1 bundle as a plain dict, ready for json.dump.
    """
    created = _now()
    objects: list[dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": TOOL_IDENTITY_ID,
            "created": created,
            "modified": created,
            "name": "threat-intel-enricher",
            "identity_class": "system",
            "description": "Automated IOC enrichment pipeline",
        }
    ]

    exported = [s for s in scores if s.is_actionable] if actionable_only else list(scores)

    for score in exported:
        pattern = build_pattern(score.ioc.type, score.ioc.value)
        if pattern is None:
            continue

        indicator_id = f"indicator--{uuid.uuid5(_NAMESPACE, score.ioc.value + score.ioc.type.value)}"
        first_seen = score.ioc.first_seen
        if first_seen.tzinfo is None:
            first_seen = first_seen.replace(tzinfo=UTC)

        labels = sorted({c for e in score.enrichments for c in e.categories if c})

        indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created_by_ref": TOOL_IDENTITY_ID,
            "created": created,
            "modified": created,
            "name": f"{score.ioc.type.value}: {score.ioc.value}",
            "description": (
                f"Risk score {score.score}/100 ({score.severity.value}) from "
                f"{score.malicious_sources} of {score.sources_reporting} sources reporting malicious."
            ),
            "indicator_types": ["malicious-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": first_seen.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "confidence": _CONFIDENCE_BY_SEVERITY[score.severity],
        }
        if labels:
            indicator["labels"] = labels
        objects.append(indicator)

        # The enrichment evidence, attached as a note. A bare indicator with a
        # score is unauditable; a downstream analyst needs to see which sources
        # said what before acting on it.
        evidence = "; ".join(
            f"{e.source}: {'malicious' if e.malicious else 'clean'} "
            f"(confidence {e.confidence:.2f})"
            + (f" [error: {e.error}]" if e.error else "")
            for e in score.enrichments
        )
        if evidence:
            objects.append(
                {
                    "type": "note",
                    "spec_version": "2.1",
                    "id": f"note--{uuid.uuid5(_NAMESPACE, indicator_id + 'evidence')}",
                    "created_by_ref": TOOL_IDENTITY_ID,
                    "created": created,
                    "modified": created,
                    "abstract": "Enrichment evidence",
                    "content": evidence,
                    "object_refs": [indicator_id],
                }
            )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


class STIXReporter(BaseReporter):
    """Renders scored IOCs as a STIX 2.1 bundle.

    Conforms to the same BaseReporter interface as the Markdown and HTML
    reporters, so the CLI can select an output format without special-casing.
    Campaigns are accepted for interface compatibility but not serialised:
    STIX models campaigns as a distinct SDO with attribution semantics this
    pipeline does not establish, and emitting under-evidenced campaign objects
    into a TIP would be worse than omitting them.
    """

    name = "stix"
    file_extension = ".stix.json"

    def __init__(self, *, actionable_only: bool = True) -> None:
        self.actionable_only = actionable_only

    def render(
        self,
        scores: list[RiskScore],
        campaigns: list[AttackCampaign],
    ) -> str:
        """Render a STIX 2.1 bundle as a JSON string."""
        bundle = build_bundle(scores, actionable_only=self.actionable_only)
        return json.dumps(bundle, indent=2)

    def write(self, scores: list[RiskScore], output_path: Path) -> Path:
        """Convenience helper: render and write to disk."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(self.render(scores, []))
        return output_path
