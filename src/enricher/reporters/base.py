"""Abstract base class for report generators."""
from __future__ import annotations

from abc import ABC, abstractmethod

from enricher.models import AttackCampaign, RiskScore


class BaseReporter(ABC):
    """Abstract base class for report generators.

    Reporters transform scored IOCs and correlated campaigns into
    human-readable (Markdown, HTML) or machine-readable (JSON) output.
    """

    name: str = ""
    file_extension: str = ""

    @abstractmethod
    def render(
        self,
        scores: list[RiskScore],
        campaigns: list[AttackCampaign],
    ) -> str:
        """Render a complete incident report from scored IOCs and campaigns."""
