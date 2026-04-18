"""Suricata EVE JSON ingester.

Parses line-delimited JSON from Suricata's EVE output, filters for alert
events, and extracts IOCs (IPs, domains, URLs) for enrichment.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from enricher.ingesters.base import BaseIngester
from enricher.models import Alert, IOC, IOCType

logger = logging.getLogger(__name__)

# RFC 1918 private address ranges — usually not worth enriching
PRIVATE_IP_PREFIXES = (
    "10.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "127.",
    "::1",
    "fe80:",
)


class SuricataIngester(BaseIngester):
    """Ingester for Suricata EVE JSON format."""

    name = "suricata_eve"

    def ingest(self, source: Path) -> Iterator[Alert]:
        """Stream alerts from a Suricata EVE JSON file.

        Each line in the file should be a JSON object. Only events with
        event_type='alert' are yielded — other events (flow, dns, http, etc.)
        are skipped.
        """
        if not source.exists():
            raise FileNotFoundError(f"EVE JSON file not found: {source}")

        with source.open("r") as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError as e:
                    logger.warning("Skipping malformed JSON at line %d: %s", line_num, e)
                    continue

                if event.get("event_type") != "alert":
                    continue

                try:
                    yield self._parse_alert(event, line_num)
                except (KeyError, ValueError) as e:
                    logger.warning("Skipping malformed alert at line %d: %s", line_num, e)

    def extract_iocs(self, alert: Alert) -> list[IOC]:
        """Extract IP, domain, and URL IOCs from an alert.

        Only extracts external (non-RFC1918) IPs — there's no value in
        enriching internal addresses.
        """
        iocs: list[IOC] = []

        # External source IP
        if not self._is_private_ip(alert.src_ip):
            iocs.append(
                IOC(
                    value=alert.src_ip,
                    type=IOCType.IP,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        # External destination IP (for outbound connections)
        if not self._is_private_ip(alert.dest_ip):
            iocs.append(
                IOC(
                    value=alert.dest_ip,
                    type=IOCType.IP,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        # DNS query domains
        if alert.dns_query:
            iocs.append(
                IOC(
                    value=alert.dns_query.lower().rstrip("."),
                    type=IOCType.DOMAIN,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        # HTTP URLs
        if alert.http_hostname and alert.http_url:
            iocs.append(
                IOC(
                    value=f"http://{alert.http_hostname}{alert.http_url}",
                    type=IOCType.URL,
                    first_seen=alert.timestamp,
                    source_alert_id=alert.id,
                )
            )

        return iocs

    @staticmethod
    def _parse_alert(event: dict[str, Any], line_num: int) -> Alert:
        """Convert a Suricata EVE alert event into our normalized Alert model."""
        alert_info = event.get("alert", {})

        return Alert(
            id=f"suricata-{line_num}-{event.get('flow_id', line_num)}",
            timestamp=datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")),
            signature=alert_info.get("signature", "Unknown"),
            severity=alert_info.get("severity", 3),
            category=alert_info.get("category", "Unknown"),
            src_ip=event.get("src_ip", ""),
            dest_ip=event.get("dest_ip", ""),
            src_port=event.get("src_port"),
            dest_port=event.get("dest_port"),
            protocol=event.get("proto"),
            dns_query=event.get("dns", {}).get("rrname") if event.get("dns") else None,
            http_hostname=event.get("http", {}).get("hostname") if event.get("http") else None,
            http_url=event.get("http", {}).get("url") if event.get("http") else None,
            raw=event,
        )

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Quick check for RFC 1918 and loopback addresses.

        Uses string prefixes for speed — acceptable for IOC filtering.
        For production use, consider ipaddress.ip_address().is_private
        """
        return ip.startswith(PRIVATE_IP_PREFIXES)
