"""Tests for the CLI and the human-readable reporters.

The CLI had zero coverage despite being the only interface most users touch.
It is tested here with click's CliRunner against real fixture files, which
exercises argument parsing, file validation, and the enricher-selection logic
without making network calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from enricher.cli import _build_enrichers, _print_scores_table, _save_json, main
from enricher.config import Settings
from enricher.models import RiskScore
from enricher.reporters import HTMLReporter, MarkdownReporter, STIXReporter
from enricher.reporters.base import BaseReporter

from .conftest import FakeSession

# --------------------------------------------------------------------------
# CLI surface
# --------------------------------------------------------------------------


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_cli_help_lists_commands(runner: CliRunner) -> None:
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    for command in ("ingest", "pipeline", "correlate"):
        assert command in result.output


def test_cli_version(runner: CliRunner) -> None:
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


@pytest.mark.parametrize("command", ["ingest", "pipeline", "correlate"])
def test_cli_subcommand_help(runner: CliRunner, command: str) -> None:
    result = runner.invoke(main, [command, "--help"])
    assert result.exit_code == 0


@pytest.mark.parametrize("command", ["ingest", "pipeline", "correlate"])
def test_cli_rejects_missing_source(runner: CliRunner, command: str) -> None:
    """Click should reject a nonexistent path before any work begins."""
    result = runner.invoke(main, [command, "--source", "/nonexistent/eve.json"])
    assert result.exit_code != 0


def test_cli_ingest_extracts_iocs(runner: CliRunner, tmp_path: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "sample_suricata_eve.json"
    if not example.exists():
        pytest.skip("bundled example not present")

    out = tmp_path / "iocs.json"
    result = runner.invoke(main, ["ingest", "--source", str(example), "--output", str(out)])

    assert result.exit_code == 0, result.output
    assert out.exists()
    payload = json.loads(out.read_text())
    assert set(payload) >= {"iocs", "alerts"}
    assert len(payload["iocs"]) > 0


def test_cli_correlate_runs(runner: CliRunner) -> None:
    example = Path(__file__).resolve().parents[1] / "examples" / "sample_suricata_eve.json"
    if not example.exists():
        pytest.skip("bundled example not present")

    result = runner.invoke(main, ["correlate", "--source", str(example)])
    assert result.exit_code == 0, result.output


# --------------------------------------------------------------------------
# Enricher selection
# --------------------------------------------------------------------------


def test_keyless_cve_enrichers_always_present() -> None:
    """KEV and EPSS need no credentials, so they must be active even with an
    entirely unconfigured environment."""
    enrichers = _build_enrichers(FakeSession(), Settings())  # type: ignore[arg-type]
    names = {e.name for e in enrichers}
    assert {"cisa_kev", "epss"} <= names


def test_keyed_enrichers_omitted_without_credentials() -> None:
    enrichers = _build_enrichers(FakeSession(), Settings())  # type: ignore[arg-type]
    names = {e.name for e in enrichers}
    assert "abuseipdb" not in names
    assert "otx" not in names
    assert "urlhaus" not in names


def test_urlhaus_requires_a_key_to_be_enabled() -> None:
    """Regression guard. URLhaus was previously constructed unconditionally on
    the assumption it needed no key; abuse.ch has rejected anonymous requests
    since 2025-06-30."""
    without = _build_enrichers(FakeSession(), Settings())  # type: ignore[arg-type]
    assert "urlhaus" not in {e.name for e in without}

    with_key = _build_enrichers(  # type: ignore[arg-type]
        FakeSession(), Settings(urlhaus_api_key="k")
    )
    assert "urlhaus" in {e.name for e in with_key}


def test_all_enrichers_enabled_with_full_config() -> None:
    settings = Settings(abuseipdb_api_key="a", otx_api_key="o", urlhaus_api_key="u")
    names = {e.name for e in _build_enrichers(FakeSession(), settings)}  # type: ignore[arg-type]
    assert names == {"cisa_kev", "epss", "urlhaus", "abuseipdb", "otx"}


# --------------------------------------------------------------------------
# CLI helpers
# --------------------------------------------------------------------------


def test_save_json_creates_parent_directories(tmp_path: Path) -> None:
    out = tmp_path / "deep" / "nested" / "data.json"
    _save_json({"a": 1}, out)
    assert json.loads(out.read_text()) == {"a": 1}


def test_print_scores_table_handles_empty_input() -> None:
    """An empty result set is a normal outcome, not an error."""
    _print_scores_table([])


def test_print_scores_table_respects_limit(sample_score: RiskScore) -> None:
    _print_scores_table([sample_score] * 50, limit=5)


# --------------------------------------------------------------------------
# Human-readable reporters
# --------------------------------------------------------------------------


def test_markdown_reporter_renders_ioc(sample_score: RiskScore) -> None:
    content = MarkdownReporter().render([sample_score], [])
    assert sample_score.ioc.value in content


def test_html_reporter_renders_document(sample_score: RiskScore) -> None:
    content = HTMLReporter().render([sample_score], [])
    assert "<html" in content.lower()
    assert sample_score.ioc.value in content


def test_reporters_handle_no_findings() -> None:
    """A clean run must still produce a report saying so, rather than
    crashing or returning nothing."""
    assert MarkdownReporter().render([], [])
    assert HTMLReporter().render([], [])
    assert STIXReporter().render([], [])


def test_all_reporters_share_the_same_interface() -> None:
    """The CLI selects a format without special-casing, so every reporter
    must be substitutable."""
    for reporter in (MarkdownReporter(), HTMLReporter(), STIXReporter()):
        assert isinstance(reporter, BaseReporter)
        assert reporter.name
        assert reporter.file_extension
        assert isinstance(reporter.render([], []), str)
