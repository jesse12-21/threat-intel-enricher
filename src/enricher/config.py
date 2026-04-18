"""Configuration and secrets management.

Loads settings from environment variables (via .env file) with sane defaults.
Never hardcodes secrets — all API keys must come from the environment.
"""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field


# Load .env file if present
load_dotenv()


class Settings(BaseModel):
    """Runtime settings loaded from environment variables."""

    abuseipdb_api_key: str | None = Field(
        default=None, description="API key for AbuseIPDB (https://www.abuseipdb.com/)"
    )
    otx_api_key: str | None = Field(
        default=None, description="API key for AlienVault OTX"
    )

    max_concurrent_requests: int = Field(default=10, ge=1, le=100)
    request_timeout_seconds: int = Field(default=30, ge=5, le=300)
    output_dir: Path = Field(default=Path("./output"))

    @classmethod
    def from_env(cls) -> "Settings":
        """Load settings from environment variables."""
        return cls(
            abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY") or None,
            otx_api_key=os.getenv("OTX_API_KEY") or None,
            max_concurrent_requests=int(os.getenv("ENRICHER_MAX_CONCURRENT_REQUESTS", "10")),
            request_timeout_seconds=int(os.getenv("ENRICHER_REQUEST_TIMEOUT", "30")),
            output_dir=Path(os.getenv("ENRICHER_OUTPUT_DIR", "./output")),
        )

    @property
    def has_any_enricher_configured(self) -> bool:
        """True if at least one API-based enricher can run.
        
        URLhaus doesn't need an API key, so enrichment always works — but
        having multiple sources is much more useful for corroboration.
        """
        return bool(self.abuseipdb_api_key or self.otx_api_key)
