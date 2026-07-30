"""Nmap CIM JSON ingester — attack-surface findings as enrichable indicators.

Consumes the newline-delimited JSON produced by the companion recon project:

    https://github.com/jesse12-21/nmap-network-recon
    python3 parsers/nmap_to_siem.py scan.xml --format json

Each line is one open port on one host, with field names already normalised to
the Splunk Common Information Model (dest, dest_port, transport, service,
service_version, src).

A note on what this ingester is for. A port scan is not an alert — nothing has
attacked anything. What a scan produces is *attack surface*: hosts and services
reachable from somewhere, some of which are running software with known
problems. Feeding that surface through the same enrichment pipeline as IDS
alerts lets one question be asked across both: which of the things I can see
are things an attacker is currently exploiting?

That question is answered by the CVE enrichers (CISA KEV, EPSS) rather than the
IP-reputation ones, which is why this ingester's value depends on service
version detection being present in the scan (-sV).
"""
from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from enricher.ingesters.base import BaseIngester
from enricher.models import IOC, Alert, IOCType

logger = logging.getLogger(__name__)

# Matches a CVE identifier anywhere in a version string. Some Nmap scripts
# (notably vulners) embed CVE IDs directly in service version output.
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NmapCIMIngester(BaseIngester):
    """Ingester for CIM-normalised Nmap scan records."""

    name = "nmap_cim"

    def ingest(self, source: Path) -> Iterator[Alert]:
        """Stream scan records from a newline-delimited JSON file.

        Each record becomes an Alert so the rest of the pipeline can treat it
        uniformly. The mapping is deliberate rather than incidental:

            severity 3 (low)  -- a scan finding is informational by default.
                                 Nothing has happened; something is merely
                                 reachable. Raising this would let attack
                                 surface outrank actual IDS alerts in scoring.
            src_ip            -- the scanning host, where recorded
            dest_ip           -- the discovered host
            signature         -- service and version, which is the finding
        """
        if not source.exists():
            raise FileNotFoundError(f"Nmap CIM JSON file not found: {source}")

        with source.open("r") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    record = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning("Skipping malformed JSON at line %d: %s", line_num, e)
                    continue

                try:
                    yield self._parse_record(record, line_num)
                except (KeyError, ValueError) as e:
                    logger.warning("Skipping malformed record at line %d: %s", line_num, e)

    def _parse_record(self, record: dict[str, Any], line_num: int) -> Alert:
        """Convert one CIM record into a normalised Alert."""
        dest = record.get("dest")
        if not dest:
            raise KeyError("record has no 'dest' field — is this nmap_to_siem.py output?")

        service = record.get("service", "unknown")
        version = record.get("service_version", "")
        signature = f"{service} {version}".strip() or "unidentified service"

        scan_start = record.get("scan_start", "")
        timestamp = self._parse_timestamp(scan_start)

        return Alert(
            id=f"nmap-{dest}-{record.get('dest_port', 0)}-{line_num}",
            timestamp=timestamp,
            signature=f"Open service: {signature}",
            severity=3,
            category="Attack Surface Discovery",
            src_ip=record.get("src") or "0.0.0.0",
            dest_ip=dest,
            dest_port=int(record["dest_port"]) if record.get("dest_port") else None,
            protocol=record.get("transport"),
            http_hostname=record.get("hostname") or None,
            raw=record,
        )

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        """Parse Nmap's startstr format, falling back to now.

        Nmap writes a human-readable timestamp like 'Mon Jul 27 09:00:00 2026'.
        A scan record with an unparseable time is still a useful finding, so
        this degrades rather than rejecting the record.
        """
        if value:
            for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(value, fmt).replace(tzinfo=UTC)
                except ValueError:
                    continue
            logger.debug("Unparseable scan_start %r; using current time", value)
        return datetime.now(UTC)

    def extract_iocs(self, alert: Alert) -> list[IOC]:
        """Extract enrichable indicators from a scan finding.

        Two kinds are produced:

          - The discovered host's IP, but only when it is externally routable.
            Enriching an RFC 1918 address against a reputation feed returns
            nothing useful and spends quota.
          - Any CVE identifiers embedded in the service version string, which
            Nmap's vulners script and similar produce. These are the indicators
            the KEV and EPSS enrichers act on.
        """
        iocs: list[IOC] = []

        if not self._is_private_ip(alert.dest_ip):
            iocs.append(
                IOC(
                    value=alert.dest_ip,
                    type=IOCType.IP,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        for match in CVE_PATTERN.findall(alert.signature):
            iocs.append(
                IOC(
                    value=match.upper(),
                    type=IOCType.CVE,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        return iocs

    @staticmethod
    def _is_private_ip(value: str) -> bool:
        """True for RFC 1918, loopback, link-local, and reserved addresses."""
        try:
            addr = ip_address(value)
        except ValueError:
            return False
        return bool(
            addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved
        )
