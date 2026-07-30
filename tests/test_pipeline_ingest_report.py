"""Tests for ingesters, pipeline orchestration, config, and STIX output.

These modules previously had zero coverage. The pattern that produced that gap
is worth naming: the three modules that *were* tested (models, scoring,
correlator) are the three pure-logic ones. Everything touching I/O was skipped,
which is precisely where the bugs were.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path

import pytest

from enricher.config import Settings
from enricher.enrichers.base import BaseEnricher, EnrichmentError, RateLimitError
from enricher.ingesters import NmapCIMIngester, SuricataIngester
from enricher.models import IOC, EnrichmentResult, IOCType, RiskScore, Severity
from enricher.pipeline import enrich_all_iocs, enrich_ioc, group_iocs_by_alert
from enricher.reporters.stix_reporter import STIXReporter, build_bundle, build_pattern

# --------------------------------------------------------------------------
# Nmap CIM ingester — the bridge from the recon project
# --------------------------------------------------------------------------

NMAP_RECORDS = [
    {
        # Routable address: RFC 5737 documentation ranges (198.51.100.0/24,
        # 203.0.113.0/24, 192.0.2.0/24) are classified as private by Python's
        # ipaddress module and are correctly skipped by the ingester — see
        # test_documentation_ranges_are_not_enrichable below.
        "dest": "45.33.32.156",
        "dest_port": 443,
        "transport": "tcp",
        "status": "open",
        "service": "https",
        "service_version": "Apache httpd 2.4.52",
        "hostname": "web01.example.invalid",
        "scan_start": "Mon Jul 27 09:00:00 2026",
        "src": "10.0.2.15",
    },
    {
        "dest": "10.0.0.5",
        "dest_port": 22,
        "transport": "tcp",
        "status": "open",
        "service": "ssh",
        "service_version": "OpenSSH 8.9p1",
        "hostname": "",
        "scan_start": "Mon Jul 27 09:00:00 2026",
        "src": "10.0.2.15",
    },
    {
        "dest": "45.33.32.157",
        "dest_port": 8080,
        "transport": "tcp",
        "status": "open",
        "service": "http",
        "service_version": "Apache Log4j CVE-2021-44228 vulnerable",
        "hostname": "",
        "scan_start": "Mon Jul 27 09:00:00 2026",
        "src": "10.0.2.15",
    },
]


@pytest.fixture
def nmap_file(tmp_path: Path) -> Path:
    path = tmp_path / "scan.json"
    path.write_text("\n".join(json.dumps(r) for r in NMAP_RECORDS) + "\n")
    return path


def test_nmap_ingester_parses_all_records(nmap_file: Path) -> None:
    alerts = list(NmapCIMIngester().ingest(nmap_file))
    assert len(alerts) == 3


def test_nmap_ingester_marks_findings_informational(nmap_file: Path) -> None:
    """A scan finding is attack surface, not an attack. Severity 3 keeps it
    from outranking real IDS alerts in downstream scoring."""
    alerts = list(NmapCIMIngester().ingest(nmap_file))
    assert all(a.severity == 3 for a in alerts)
    assert all(a.category == "Attack Surface Discovery" for a in alerts)


def test_nmap_ingester_skips_private_ips(nmap_file: Path) -> None:
    """Enriching an RFC 1918 address against a reputation feed returns nothing
    and spends quota."""
    ingester = NmapCIMIngester()
    iocs = list(ingester.ingest_all_iocs(nmap_file))
    values = {i.value for i in iocs}
    assert "10.0.0.5" not in values
    assert "45.33.32.156" in values


def test_documentation_ranges_are_not_enrichable(tmp_path: Path) -> None:
    """RFC 5737 documentation addresses are classified private by Python and
    are correctly skipped. Worth asserting because sample data commonly uses
    them, and a demo that silently produces no IP IOCs is confusing.
    """
    record = dict(NMAP_RECORDS[0], dest="198.51.100.10")
    path = tmp_path / "docrange.json"
    path.write_text(json.dumps(record) + "\n")

    iocs = list(NmapCIMIngester().ingest_all_iocs(path))

    assert not [i for i in iocs if i.type == IOCType.IP]


def test_nmap_ingester_extracts_embedded_cves(nmap_file: Path) -> None:
    """Nmap's vulners script embeds CVE IDs in version output. Those are the
    indicators the KEV and EPSS enrichers act on."""
    iocs = list(NmapCIMIngester().ingest_all_iocs(nmap_file))
    cves = [i for i in iocs if i.type == IOCType.CVE]
    assert len(cves) == 1
    assert cves[0].value == "CVE-2021-44228"


def test_nmap_ingester_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "mixed.json"
    path.write_text(
        json.dumps(NMAP_RECORDS[0]) + "\n" + "{not valid json\n" + json.dumps(NMAP_RECORDS[2]) + "\n"
    )
    alerts = list(NmapCIMIngester().ingest(path))
    assert len(alerts) == 2


def test_nmap_ingester_rejects_non_nmap_json(tmp_path: Path) -> None:
    path = tmp_path / "wrong.json"
    path.write_text(json.dumps({"unrelated": "data"}) + "\n")
    alerts = list(NmapCIMIngester().ingest(path))
    assert alerts == [], "a record with no 'dest' field should be skipped, not crash"


def test_nmap_ingester_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        list(NmapCIMIngester().ingest(Path("/nonexistent/scan.json")))


def test_nmap_ingester_handles_unparseable_timestamp(tmp_path: Path) -> None:
    record = dict(NMAP_RECORDS[0], scan_start="not a timestamp")
    path = tmp_path / "bad_time.json"
    path.write_text(json.dumps(record) + "\n")
    alerts = list(NmapCIMIngester().ingest(path))
    assert len(alerts) == 1, "a bad timestamp should degrade, not reject the finding"


# --------------------------------------------------------------------------
# Suricata ingester
# --------------------------------------------------------------------------


def test_suricata_ingester_reads_bundled_example() -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "sample_suricata_eve.json"
    if not example.exists():
        pytest.skip("bundled example not present")
    alerts = list(SuricataIngester().ingest(example))
    assert len(alerts) > 0
    assert all(a.signature for a in alerts)


def test_suricata_ingester_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        list(SuricataIngester().ingest(Path("/nonexistent/eve.json")))


def test_suricata_ingester_skips_non_alert_events(tmp_path: Path) -> None:
    path = tmp_path / "eve.json"
    path.write_text(
        json.dumps({"event_type": "flow", "flow_id": 1}) + "\n"
        + json.dumps({"event_type": "dns", "dns": {}}) + "\n"
    )
    assert list(SuricataIngester().ingest(path)) == []


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------


class StubEnricher(BaseEnricher):
    """Enricher that records calls and can be told to misbehave."""

    def __init__(
        self, name: str, types: list[IOCType], *, raises: Exception | None = None
    ) -> None:
        self.name = name
        self.supported_ioc_types = types
        self._raises = raises
        self.seen: list[str] = []

    async def enrich(self, ioc: IOC) -> EnrichmentResult | None:
        self.seen.append(ioc.value)
        if self._raises is not None:
            raise self._raises
        return EnrichmentResult(ioc=ioc, source=self.name, malicious=True, confidence=0.5)


async def test_pipeline_queries_only_applicable_enrichers(ip_ioc: IOC) -> None:
    ip_only = StubEnricher("ip-source", [IOCType.IP])
    url_only = StubEnricher("url-source", [IOCType.URL])

    results = await enrich_ioc(ip_ioc, [ip_only, url_only], asyncio.Semaphore(5))

    assert len(results) == 1
    assert ip_only.seen == [ip_ioc.value]
    assert url_only.seen == []


async def test_pipeline_returns_empty_when_nothing_applies(cve_ioc: IOC) -> None:
    results = await enrich_ioc(cve_ioc, [StubEnricher("ip", [IOCType.IP])], asyncio.Semaphore(5))
    assert results == []


async def test_pipeline_survives_rate_limit(ip_ioc: IOC) -> None:
    """One source hitting a rate limit must not lose the others' results."""
    good = StubEnricher("good", [IOCType.IP])
    limited = StubEnricher("limited", [IOCType.IP], raises=RateLimitError("429"))

    results = await enrich_ioc(ip_ioc, [good, limited], asyncio.Semaphore(5))

    assert len(results) == 1
    assert results[0].source == "good"


async def test_pipeline_survives_enrichment_error(ip_ioc: IOC) -> None:
    good = StubEnricher("good", [IOCType.IP])
    broken = StubEnricher("broken", [IOCType.IP], raises=EnrichmentError("bad key"))

    results = await enrich_ioc(ip_ioc, [good, broken], asyncio.Semaphore(5))

    assert len(results) == 1


async def test_pipeline_deduplicates_iocs(fixed_time: datetime) -> None:
    """The same indicator across many alerts must be enriched once. Without
    dedup, a campaign of 500 alerts from one IP costs 500 API calls."""
    duplicates = [
        IOC(value="198.51.100.10", type=IOCType.IP, first_seen=fixed_time, source_alert_id=f"a{n}")
        for n in range(10)
    ]
    source = StubEnricher("s", [IOCType.IP])

    results = await enrich_all_iocs(duplicates, [source])

    assert len(source.seen) == 1
    assert len(results) == 1


def test_group_iocs_by_alert(ip_ioc: IOC) -> None:
    score = RiskScore(
        ioc=ip_ioc, score=50, severity=Severity.MEDIUM, sources_reporting=1, malicious_sources=1
    )
    grouped = group_iocs_by_alert([], [score])
    assert grouped[ip_ioc.source_alert_id] == [score]


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------


def test_settings_read_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "abc")
    monkeypatch.setenv("URLHAUS_API_KEY", "xyz")
    monkeypatch.setenv("ENRICHER_MAX_CONCURRENT_REQUESTS", "25")

    settings = Settings.from_env()

    assert settings.abuseipdb_api_key == "abc"
    assert settings.urlhaus_api_key == "xyz"
    assert settings.max_concurrent_requests == 25


def test_empty_env_var_becomes_none(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unset key in .env arrives as an empty string, which must not be
    treated as a usable credential."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "")
    assert Settings.from_env().abuseipdb_api_key is None


def test_urlhaus_key_counts_as_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """URLhaus stopped being a keyless fallback on 2025-06-30, so it now
    counts toward having any enricher configured."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("OTX_API_KEY", raising=False)
    monkeypatch.setenv("URLHAUS_API_KEY", "k")

    assert Settings.from_env().has_any_enricher_configured is True


def test_no_keys_means_nothing_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("ABUSEIPDB_API_KEY", "OTX_API_KEY", "URLHAUS_API_KEY"):
        monkeypatch.setenv(var, "")
    assert Settings.from_env().has_any_enricher_configured is False


# --------------------------------------------------------------------------
# STIX 2.1 reporter
# --------------------------------------------------------------------------


def test_stix_patterns_per_ioc_type() -> None:
    assert build_pattern(IOCType.IP, "1.2.3.4") == "[ipv4-addr:value = '1.2.3.4']"
    assert build_pattern(IOCType.DOMAIN, "evil.invalid") == "[domain-name:value = 'evil.invalid']"
    assert build_pattern(IOCType.CVE, "CVE-2021-44228") == "[vulnerability:name = 'CVE-2021-44228']"
    assert "SHA-256" in (build_pattern(IOCType.HASH_SHA256, "abc") or "")


def test_stix_pattern_escapes_quotes() -> None:
    """URLs routinely contain quotes and backslashes; an unescaped one breaks
    the pattern and can corrupt the bundle."""
    pattern = build_pattern(IOCType.URL, "http://evil.invalid/it's\\bad")
    assert pattern is not None
    assert "\\'" in pattern
    assert "\\\\" in pattern


def test_stix_bundle_structure(sample_score: RiskScore) -> None:
    bundle = build_bundle([sample_score])

    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    types = [o["type"] for o in bundle["objects"]]
    assert "identity" in types
    assert "indicator" in types
    assert "note" in types
    assert all(o["spec_version"] == "2.1" for o in bundle["objects"])


def test_stix_indicator_carries_confidence(sample_score: RiskScore) -> None:
    bundle = build_bundle([sample_score])
    indicator = next(o for o in bundle["objects"] if o["type"] == "indicator")
    assert indicator["confidence"] == 95  # CRITICAL
    assert indicator["pattern_type"] == "stix"


def test_stix_note_records_enrichment_evidence(sample_score: RiskScore) -> None:
    """A bare indicator with a score is unauditable — a downstream analyst
    needs to see which sources said what."""
    bundle = build_bundle([sample_score])
    note = next(o for o in bundle["objects"] if o["type"] == "note")
    assert "abuseipdb" in note["content"]
    assert "otx" in note["content"]


def test_stix_excludes_non_actionable_by_default(ip_ioc: IOC) -> None:
    """A bundle full of INFO indicators dilutes a TIP feed and trains
    analysts to ignore it."""
    low = RiskScore(
        ioc=ip_ioc, score=5, severity=Severity.INFO, sources_reporting=1, malicious_sources=0
    )
    assert not any(o["type"] == "indicator" for o in build_bundle([low])["objects"])
    assert any(
        o["type"] == "indicator" for o in build_bundle([low], actionable_only=False)["objects"]
    )


def test_stix_identity_id_is_stable_across_runs(sample_score: RiskScore) -> None:
    """STIX consumers deduplicate on ID. A fresh identity UUID each run would
    create a new producer in the TIP on every execution."""
    a = build_bundle([sample_score])
    b = build_bundle([sample_score])
    id_a = next(o for o in a["objects"] if o["type"] == "identity")["id"]
    id_b = next(o for o in b["objects"] if o["type"] == "identity")["id"]
    assert id_a == id_b


def test_stix_reporter_writes_valid_json(sample_score: RiskScore, tmp_path: Path) -> None:
    out = tmp_path / "nested" / "bundle.stix.json"
    written = STIXReporter().write([sample_score], out)

    assert written.exists()
    loaded = json.loads(written.read_text())
    assert loaded["type"] == "bundle"
