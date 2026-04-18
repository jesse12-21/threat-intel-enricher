"""HTML incident report generator.

Produces styled, standalone HTML reports suitable for sharing with
stakeholders or embedding in ticketing systems that render HTML.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from jinja2 import Environment, select_autoescape

from enricher.models import AttackCampaign, RiskScore, Severity
from enricher.reporters.base import BaseReporter


SEVERITY_COLORS = {
    Severity.CRITICAL: "#dc2626",
    Severity.HIGH: "#ea580c",
    Severity.MEDIUM: "#ca8a04",
    Severity.LOW: "#16a34a",
    Severity.INFO: "#6b7280",
}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Incident Report — {{ generated_at.strftime('%Y-%m-%d') }}</title>
<style>
  :root {
    --bg: #0f172a;
    --card: #1e293b;
    --border: #334155;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --accent: #3b82f6;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2rem;
    line-height: 1.6;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  header {
    border-bottom: 2px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }
  h1 { margin: 0 0 0.5rem; font-size: 2rem; }
  h2 {
    border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem;
    margin-top: 2.5rem;
  }
  h3 { color: var(--accent); margin-top: 2rem; }
  .meta { color: var(--muted); font-size: 0.9rem; }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1rem;
    margin: 1.5rem 0;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
  }
  .stat-card .count { font-size: 2rem; font-weight: 700; }
  .stat-card .label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; }
  table {
    width: 100%;
    border-collapse: collapse;
    background: var(--card);
    border-radius: 8px;
    overflow: hidden;
    margin: 1rem 0;
  }
  th, td {
    padding: 0.75rem 1rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
  }
  th {
    background: rgba(59, 130, 246, 0.1);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.85rem;
    color: var(--muted);
  }
  tr:last-child td { border-bottom: none; }
  tr:hover { background: rgba(255, 255, 255, 0.03); }
  code {
    background: rgba(148, 163, 184, 0.15);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-family: 'SF Mono', Monaco, Consolas, monospace;
    font-size: 0.9em;
  }
  .severity-badge {
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    color: white;
  }
  .campaign-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-left: 4px solid var(--accent);
    border-radius: 8px;
    padding: 1.25rem;
    margin: 1rem 0;
  }
  .campaign-card .signatures {
    margin-top: 0.75rem;
    font-size: 0.9rem;
  }
  .signature-pill {
    display: inline-block;
    background: rgba(59, 130, 246, 0.15);
    padding: 0.2rem 0.6rem;
    margin: 0.2rem 0.2rem 0.2rem 0;
    border-radius: 4px;
    font-size: 0.85rem;
  }
  .summary-banner {
    padding: 1.25rem;
    border-radius: 8px;
    margin: 1.5rem 0;
    border-left: 4px solid var(--accent);
    background: var(--card);
  }
  .summary-banner.critical { border-left-color: #dc2626; }
  .summary-banner.high { border-left-color: #ea580c; }
  footer {
    margin-top: 3rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border);
    color: var(--muted);
    font-size: 0.85rem;
    text-align: center;
  }
</style>
</head>
<body>
<div class="container">

<header>
  <h1>🚨 Security Incident Report</h1>
  <div class="meta">
    Generated: {{ generated_at.strftime('%Y-%m-%d %H:%M:%S UTC') }}
    · Total IOCs: {{ stats.total_iocs }}
    · Campaigns: {{ stats.total_campaigns }}
  </div>
</header>

<div class="summary-banner {% if stats.critical_count > 0 %}critical{% elif stats.high_count > 0 %}high{% endif %}">
{% if stats.critical_count > 0 -%}
  <strong>⚠️ {{ stats.critical_count }} critical-severity indicator(s) detected.</strong>
  Immediate analyst review recommended.
{%- elif stats.high_count > 0 -%}
  <strong>{{ stats.high_count }} high-severity indicator(s) detected.</strong>
  Review within standard SLA.
{%- else -%}
  No critical or high-severity indicators found in this batch.
{%- endif %}
</div>

<h2>Severity Distribution</h2>

<div class="stats-grid">
  <div class="stat-card" style="border-color: {{ severity_colors['critical'] }};">
    <div class="count" style="color: {{ severity_colors['critical'] }};">{{ stats.critical_count }}</div>
    <div class="label">🔴 Critical</div>
  </div>
  <div class="stat-card" style="border-color: {{ severity_colors['high'] }};">
    <div class="count" style="color: {{ severity_colors['high'] }};">{{ stats.high_count }}</div>
    <div class="label">🟠 High</div>
  </div>
  <div class="stat-card" style="border-color: {{ severity_colors['medium'] }};">
    <div class="count" style="color: {{ severity_colors['medium'] }};">{{ stats.medium_count }}</div>
    <div class="label">🟡 Medium</div>
  </div>
  <div class="stat-card" style="border-color: {{ severity_colors['low'] }};">
    <div class="count" style="color: {{ severity_colors['low'] }};">{{ stats.low_count }}</div>
    <div class="label">🟢 Low</div>
  </div>
  <div class="stat-card" style="border-color: {{ severity_colors['info'] }};">
    <div class="count" style="color: {{ severity_colors['info'] }};">{{ stats.info_count }}</div>
    <div class="label">⚪ Info</div>
  </div>
</div>

<h2>🎯 Attack Campaigns</h2>

{% if campaigns %}
<p>{{ campaigns|length }} coordinated attack campaign(s) detected by grouping alerts from the same source IP within a 15-minute time window.</p>

{% for campaign in campaigns[:10] %}
<div class="campaign-card">
  <h3 style="margin-top: 0;">Campaign {{ loop.index }}: <code>{{ campaign.attacker_ip }}</code></h3>
  <div><strong>Alert Count:</strong> {{ campaign.alert_count }}</div>
  <div><strong>Duration:</strong> {{ (campaign.end_time - campaign.start_time).total_seconds()|int }} seconds</div>
  <div><strong>Window:</strong> {{ campaign.start_time.strftime('%Y-%m-%d %H:%M:%S') }} → {{ campaign.end_time.strftime('%H:%M:%S UTC') }}</div>
  <div><strong>Top Signature:</strong> {{ campaign.top_signature }}</div>
  <div class="signatures">
    <strong>Signatures:</strong><br>
    {% for sig in campaign.signatures[:10] %}
    <span class="signature-pill">{{ sig }}</span>
    {% endfor %}
  </div>
</div>
{% endfor %}
{% else %}
<p>No attack campaigns identified. Alerts appear isolated rather than coordinated.</p>
{% endif %}

<h2>🔍 Top Scored Indicators of Compromise</h2>

{% if top_iocs %}
<table>
  <thead>
    <tr>
      <th>Rank</th>
      <th>Severity</th>
      <th>Score</th>
      <th>IOC</th>
      <th>Type</th>
      <th>Sources</th>
      <th>Verdict</th>
    </tr>
  </thead>
  <tbody>
  {% for score in top_iocs %}
    <tr>
      <td>{{ loop.index }}</td>
      <td><span class="severity-badge" style="background: {{ severity_colors[score.severity.value] }};">{{ score.severity.value }}</span></td>
      <td><strong>{{ score.score }}</strong>/100</td>
      <td><code>{{ score.ioc.value }}</code></td>
      <td>{{ score.ioc.type.value }}</td>
      <td>{{ score.sources_reporting }}</td>
      <td>{{ score.malicious_sources }} malicious</td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% else %}
<p>No IOCs met the scoring threshold for this report.</p>
{% endif %}

<footer>
  Generated by threat-intel-enricher v0.1.0 · Data sources: AbuseIPDB, URLhaus, AlienVault OTX
</footer>

</div>
</body>
</html>
"""


class HTMLReporter(BaseReporter):
    """Generate styled HTML incident reports."""

    name = "html"
    file_extension = "html"

    def __init__(self) -> None:
        self.env = Environment(autoescape=select_autoescape(["html", "xml"]))
        self.template = self.env.from_string(HTML_TEMPLATE)

    def render(
        self,
        scores: list[RiskScore],
        campaigns: list[AttackCampaign],
    ) -> str:
        return self.template.render(
            generated_at=datetime.now(timezone.utc),
            campaigns=campaigns,
            top_iocs=scores[:30],
            stats=_calculate_stats(scores, campaigns),
            severity_colors={s.value: color for s, color in SEVERITY_COLORS.items()},
        )


def _calculate_stats(scores: list[RiskScore], campaigns: list[AttackCampaign]) -> dict[str, Any]:
    by_severity: dict[Severity, int] = {s: 0 for s in Severity}
    for score in scores:
        by_severity[score.severity] += 1
    return {
        "total_iocs": len(scores),
        "total_campaigns": len(campaigns),
        "critical_count": by_severity[Severity.CRITICAL],
        "high_count": by_severity[Severity.HIGH],
        "medium_count": by_severity[Severity.MEDIUM],
        "low_count": by_severity[Severity.LOW],
        "info_count": by_severity[Severity.INFO],
    }
