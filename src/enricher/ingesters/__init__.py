"""Alert ingestion modules — parse logs from various IDS/SIEM sources."""
from enricher.ingesters.base import BaseIngester
from enricher.ingesters.nmap_cim import NmapCIMIngester
from enricher.ingesters.suricata import SuricataIngester

__all__ = [
    "BaseIngester",
    "NmapCIMIngester",
    "SuricataIngester",
]
