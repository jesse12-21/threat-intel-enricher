"""Alert ingestion modules — parse logs from various IDS/SIEM sources."""
from enricher.ingesters.base import BaseIngester
from enricher.ingesters.suricata import SuricataIngester

__all__ = ["BaseIngester", "SuricataIngester"]
