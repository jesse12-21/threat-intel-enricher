"""Abstract base class for alert ingesters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from enricher.models import IOC, Alert


class BaseIngester(ABC):
    """Abstract base class for parsing alerts from IDS/SIEM sources.

    Concrete ingesters implement the source-specific parsing logic while
    conforming to a standardized interface that produces Alert objects
    and extracts IOCs.
    """

    name: str = ""

    @abstractmethod
    def ingest(self, source: Path) -> Iterator[Alert]:
        """Stream alerts from the given source file.

        Uses an iterator pattern to handle large files efficiently —
        alerts are yielded one at a time rather than loaded into memory.
        """
        ...

    @abstractmethod
    def extract_iocs(self, alert: Alert) -> list[IOC]:
        """Extract Indicators of Compromise from a single alert."""
        ...

    def ingest_all_iocs(self, source: Path) -> Iterator[IOC]:
        """Convenience method: yield all IOCs across all alerts in a source."""
        for alert in self.ingest(source):
            yield from self.extract_iocs(alert)
