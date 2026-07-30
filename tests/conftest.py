"""Shared test fixtures.

The central piece here is FakeSession, a stand-in for aiohttp.ClientSession.
The enrichers were previously untested because mocking aiohttp's async context
manager protocol is fiddly enough to discourage it — which is exactly how a
retry decorator that never retried and an authentication header that was never
sent both survived in the codebase.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import aiohttp
import pytest

from enricher.models import IOC, EnrichmentResult, IOCType, RiskScore, Severity


class FakeResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(
        self,
        *,
        status: int = 200,
        payload: Any = None,
        raise_on_status: Exception | None = None,
    ) -> None:
        self.status = status
        self._payload = payload if payload is not None else {}
        self._raise_on_status = raise_on_status

    async def json(self, **kwargs: Any) -> Any:
        return self._payload

    def raise_for_status(self) -> None:
        if self._raise_on_status is not None:
            raise self._raise_on_status
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                request_info=None,  # type: ignore[arg-type]
                history=(),
                status=self.status,
            )


class _RequestContext:
    """Async context manager returned by FakeSession.get/post."""

    def __init__(self, session: FakeSession, response: Any) -> None:
        self._session = session
        self._response = response

    async def __aenter__(self) -> Any:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def __aexit__(self, *exc: object) -> bool:
        return False


class FakeSession:
    """Records requests and replays queued responses.

    Responses may be FakeResponse instances or Exception instances; an
    exception is raised on entering the context, simulating a transport
    failure. A single response is reused for every call, which is what makes
    retry-count assertions possible.
    """

    def __init__(self, response: Any = None, *, responses: list[Any] | None = None) -> None:
        self._single = response
        self._queue = list(responses) if responses else None
        self.calls: list[dict[str, Any]] = []

    def _next(self) -> Any:
        if self._queue is not None:
            return self._queue.pop(0) if self._queue else self._single
        return self._single

    def _record(self, method: str, url: str, kwargs: dict[str, Any]) -> _RequestContext:
        self.calls.append({"method": method, "url": url, **kwargs})
        return _RequestContext(self, self._next())

    def get(self, url: str, **kwargs: Any) -> _RequestContext:
        return self._record("GET", url, kwargs)

    def post(self, url: str, **kwargs: Any) -> _RequestContext:
        return self._record("POST", url, kwargs)

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def last_headers(self) -> dict[str, str]:
        return dict(self.calls[-1].get("headers") or {}) if self.calls else {}


# --------------------------------------------------------------------------
# Common objects
# --------------------------------------------------------------------------


@pytest.fixture
def fixed_time() -> datetime:
    return datetime(2026, 7, 29, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def ip_ioc(fixed_time: datetime) -> IOC:
    return IOC(
        value="198.51.100.10", type=IOCType.IP, first_seen=fixed_time, source_alert_id="alert-1"
    )


@pytest.fixture
def url_ioc(fixed_time: datetime) -> IOC:
    return IOC(
        value="http://malware.invalid/payload.exe",
        type=IOCType.URL,
        first_seen=fixed_time,
        source_alert_id="alert-2",
    )


@pytest.fixture
def domain_ioc(fixed_time: datetime) -> IOC:
    return IOC(
        value="malware.invalid",
        type=IOCType.DOMAIN,
        first_seen=fixed_time,
        source_alert_id="alert-3",
    )


@pytest.fixture
def cve_ioc(fixed_time: datetime) -> IOC:
    return IOC(
        value="CVE-2021-44228",
        type=IOCType.CVE,
        first_seen=fixed_time,
        source_alert_id="alert-4",
    )


@pytest.fixture
def sample_score(ip_ioc: IOC) -> RiskScore:
    return RiskScore(
        ioc=ip_ioc,
        score=85,
        severity=Severity.CRITICAL,
        sources_reporting=2,
        malicious_sources=2,
        enrichments=[
            EnrichmentResult(
                ioc=ip_ioc,
                source="abuseipdb",
                malicious=True,
                confidence=0.9,
                categories=["ssh-bruteforce"],
            ),
            EnrichmentResult(
                ioc=ip_ioc, source="otx", malicious=True, confidence=0.7, categories=["botnet"]
            ),
        ],
    )
