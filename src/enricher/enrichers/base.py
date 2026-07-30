"""Abstract base class for threat intelligence enrichers."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

import aiohttp

from enricher.models import IOC, EnrichmentResult, IOCType


class EnrichmentError(Exception):
    """Raised when an enricher encounters an unrecoverable error."""


class RateLimitError(EnrichmentError):
    """Raised when an enricher hits a rate limit — callers should back off."""


class BaseEnricher(ABC):
    """Abstract base class for threat intelligence enrichers.

    Every enricher must:
      1. Declare which IOC types it supports
      2. Implement enrich() to query its backing service
      3. Return a standardized EnrichmentResult

    This uniform interface enables pluggable composition — new enrichers
    can be added without touching pipeline orchestration code.
    """

    name: str = ""
    supported_ioc_types: ClassVar[list[IOCType]] = []

    def __init__(self, session: aiohttp.ClientSession) -> None:
        self.session = session

    @abstractmethod
    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        """Query this source for information about the given IOC.

        Args:
            ioc: The indicator to look up

        Returns:
            EnrichmentResult if the IOC is supported and data was found,
            None if the IOC type is unsupported or no data exists.

        Raises:
            RateLimitError: When the API rate limit has been hit
            EnrichmentError: For other unrecoverable failures
        """

    def supports(self, ioc: IOC) -> bool:
        """Check if this enricher can process the given IOC type."""
        return ioc.type in self.supported_ioc_types
