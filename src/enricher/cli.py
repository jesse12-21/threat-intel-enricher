"""Command-line interface for the threat intelligence enricher.

Built on Click for composable subcommands and Rich for beautiful terminal
output. Subcommands can be chained or run independently via the full pipeline.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path

import aiohttp
import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from enricher.config import Settings
from enricher.correlator import correlate_by_attacker
from enricher.enrichers import AbuseIPDBEnricher, OTXEnricher, URLhausEnricher
from enricher.enrichers.base import BaseEnricher
from enricher.ingesters import SuricataIngester
from enricher.models import Alert, IOC, RiskScore, Severity
from enricher.pipeline import enrich_all_iocs
from enricher.reporters import HTMLReporter, MarkdownReporter
from enricher.scoring import score_many

console = Console()


# ---- Logging setup ---------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(console=console, rich_tracebacks=True, show_path=False)],
)
logger = logging.getLogger("enricher")


# ---- Helper functions ------------------------------------------------------


def _build_enrichers(session: aiohttp.ClientSession, settings: Settings) -> list[BaseEnricher]:
    """Build the list of active enrichers based on available API keys."""
    enrichers: list[BaseEnricher] = [URLhausEnricher(session)]  # No key needed

    if settings.abuseipdb_api_key:
        enrichers.append(AbuseIPDBEnricher(session, settings.abuseipdb_api_key))
    else:
        console.print("[yellow]⚠ AbuseIPDB API key not configured — skipping[/yellow]")

    if settings.otx_api_key:
        enrichers.append(OTXEnricher(session, settings.otx_api_key))
    else:
        console.print("[yellow]⚠ OTX API key not configured — skipping[/yellow]")

    return enrichers


def _print_scores_table(scores: list[RiskScore], limit: int = 20) -> None:
    """Render a Rich table of the top-scored IOCs."""
    severity_styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold yellow",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "green",
        Severity.INFO: "dim",
    }

    table = Table(title=f"Top {limit} Scored IOCs", show_lines=False)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Score", justify="right", width=7)
    table.add_column("IOC")
    table.add_column("Type", width=8)
    table.add_column("Sources", justify="right", width=8)

    for idx, score in enumerate(scores[:limit], start=1):
        style = severity_styles[score.severity]
        table.add_row(
            str(idx),
            f"[{style}]{score.severity.value.upper()}[/{style}]",
            str(score.score),
            score.ioc.value,
            score.ioc.type.value,
            str(score.sources_reporting),
        )

    console.print(table)


def _save_json(obj: object, path: Path) -> None:
    """Save any Pydantic-serializable object to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        json.dump(
            obj,
            f,
            indent=2,
            default=lambda o: o.model_dump(mode="json") if hasattr(o, "model_dump") else str(o),
        )


# ---- CLI commands ----------------------------------------------------------


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.1.0")
def main() -> None:
    """🐍 Threat Intelligence Enricher — SOC automation for IDS alerts.

    Ingest Suricata alerts, enrich IOCs against multiple threat intelligence
    sources, score risk, correlate attack campaigns, and generate incident reports.
    """


@main.command()
@click.option(
    "--source",
    "-s",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to Suricata EVE JSON file",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=Path("output/iocs.json"),
    help="Where to write extracted IOCs",
)
def ingest(source: Path, output: Path) -> None:
    """Parse Suricata EVE JSON and extract IOCs."""
    console.print(f"[cyan]📥 Ingesting alerts from[/cyan] {source}")

    ingester = SuricataIngester()
    alerts: list[Alert] = list(ingester.ingest(source))
    iocs: list[IOC] = []
    for alert in alerts:
        iocs.extend(ingester.extract_iocs(alert))

    unique_iocs = list(set(iocs))

    console.print(f"[green]✓[/green] Parsed {len(alerts)} alerts")
    console.print(f"[green]✓[/green] Extracted {len(iocs)} IOCs ({len(unique_iocs)} unique)")

    _save_json({"iocs": unique_iocs, "alerts": alerts}, output)
    console.print(f"[green]✓[/green] Saved to {output}")


@main.command()
@click.option(
    "--source",
    "-s",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to Suricata EVE JSON file",
)
@click.option(
    "--format",
    "-f",
    type=click.Choice(["markdown", "html", "both"], case_sensitive=False),
    default="html",
    help="Report output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=Path("output/incident_report"),
    help="Output file (extension added automatically)",
)
def pipeline(source: Path, format: str, output: Path) -> None:
    """Run the full pipeline: ingest → enrich → score → correlate → report."""
    asyncio.run(_run_pipeline(source, format, output))


async def _run_pipeline(source: Path, format: str, output: Path) -> None:
    settings = Settings.from_env()

    console.rule("[bold cyan]Threat Intelligence Enrichment Pipeline[/bold cyan]")

    # --- Stage 1: Ingest ---
    with console.status("[cyan]Parsing Suricata alerts..."):
        ingester = SuricataIngester()
        alerts = list(ingester.ingest(source))
        all_iocs: list[IOC] = []
        for alert in alerts:
            all_iocs.extend(ingester.extract_iocs(alert))
        unique_iocs = list(set(all_iocs))

    console.print(f"[green]✓[/green] Ingested {len(alerts)} alerts → {len(unique_iocs)} unique IOCs")

    if not unique_iocs:
        console.print("[yellow]⚠ No IOCs extracted — nothing to enrich. Exiting.[/yellow]")
        return

    # --- Stage 2: Enrich ---
    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=settings.request_timeout_seconds)
    ) as session:
        enrichers = _build_enrichers(session, settings)
        console.print(f"[cyan]Using {len(enrichers)} threat intel source(s):[/cyan] "
                      + ", ".join(e.name for e in enrichers))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Enriching IOCs...", total=len(unique_iocs))
            enrichments = await enrich_all_iocs(
                unique_iocs, enrichers, settings.max_concurrent_requests
            )
            progress.update(task, completed=len(unique_iocs))

    total_enrichments = sum(len(v) for v in enrichments.values())
    console.print(f"[green]✓[/green] Got {total_enrichments} enrichment results")

    # --- Stage 3: Score ---
    with console.status("[cyan]Scoring IOCs..."):
        scores = score_many(enrichments)

    actionable = [s for s in scores if s.is_actionable]
    console.print(f"[green]✓[/green] Scored {len(scores)} IOCs — {len(actionable)} actionable")

    _print_scores_table(scores, limit=10)

    # --- Stage 4: Correlate ---
    with console.status("[cyan]Correlating attack campaigns..."):
        campaigns = correlate_by_attacker(alerts, time_window_minutes=15)

    console.print(f"[green]✓[/green] Identified {len(campaigns)} attack campaign(s)")

    # --- Stage 5: Report ---
    reporters = {
        "markdown": MarkdownReporter(),
        "html": HTMLReporter(),
    }
    formats = ["markdown", "html"] if format == "both" else [format]

    for fmt in formats:
        reporter = reporters[fmt]
        content = reporter.render(scores, campaigns)
        out_path = output.with_suffix(f".{reporter.file_extension}")
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content)
        console.print(f"[green]✓[/green] {fmt.title()} report: [link]{out_path}[/link]")

    console.rule("[bold green]Pipeline complete[/bold green]")


@main.command()
@click.option(
    "--source",
    "-s",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Path to Suricata EVE JSON file",
)
def correlate(source: Path) -> None:
    """Correlate alerts into attack campaigns (no enrichment)."""
    console.print(f"[cyan]📥 Loading alerts from[/cyan] {source}")

    ingester = SuricataIngester()
    alerts = list(ingester.ingest(source))
    campaigns = correlate_by_attacker(alerts, time_window_minutes=15)

    console.print(f"[green]✓[/green] Found {len(campaigns)} attack campaigns\n")

    table = Table(title="Attack Campaigns (by alert count)")
    table.add_column("#", style="dim", width=4)
    table.add_column("Attacker IP", style="bold red")
    table.add_column("Alerts", justify="right")
    table.add_column("Duration (s)", justify="right")
    table.add_column("Top Signature")

    for idx, campaign in enumerate(campaigns[:20], start=1):
        table.add_row(
            str(idx),
            campaign.attacker_ip,
            str(campaign.alert_count),
            f"{campaign.duration_seconds:.0f}",
            campaign.top_signature or "—",
        )

    console.print(table)


if __name__ == "__main__":
    main()
