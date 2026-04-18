"""Alert correlation — grouping related alerts into attack campaigns.

Individual alerts are noise. Correlated alerts tell a story. This module
clusters alerts by source IP and time proximity to surface coordinated
attack campaigns, scanning activity, and staged intrusions.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta

from enricher.models import Alert, AttackCampaign


def correlate_by_attacker(
    alerts: list[Alert],
    time_window_minutes: int = 15,
    min_campaign_size: int = 2,
) -> list[AttackCampaign]:
    """Group alerts into attack campaigns by source IP and time proximity.

    Two alerts belong to the same campaign if they share a source IP
    and occur within time_window_minutes of each other.

    Args:
        alerts: The alerts to correlate
        time_window_minutes: Alerts within this window are part of the same campaign
        min_campaign_size: Ignore isolated alerts (clusters smaller than this)

    Returns:
        List of attack campaigns sorted by alert count (most aggressive first)
    """
    if not alerts:
        return []

    by_src_ip: dict[str, list[Alert]] = defaultdict(list)
    for alert in alerts:
        by_src_ip[alert.src_ip].append(alert)

    campaigns: list[AttackCampaign] = []
    window = timedelta(minutes=time_window_minutes)

    for src_ip, ip_alerts in by_src_ip.items():
        sorted_alerts = sorted(ip_alerts, key=lambda a: a.timestamp)
        clusters = _time_cluster(sorted_alerts, window)

        for cluster in clusters:
            if len(cluster) < min_campaign_size:
                continue

            signatures = [a.signature for a in cluster]
            signature_counts = Counter(signatures)
            top_sig = signature_counts.most_common(1)[0][0]

            campaigns.append(
                AttackCampaign(
                    attacker_ip=src_ip,
                    start_time=cluster[0].timestamp,
                    end_time=cluster[-1].timestamp,
                    alert_count=len(cluster),
                    signatures=sorted(set(signatures)),
                    alerts=cluster,
                    top_signature=top_sig,
                )
            )

    return sorted(campaigns, key=lambda c: c.alert_count, reverse=True)


def _time_cluster(
    sorted_alerts: list[Alert], window: timedelta
) -> list[list[Alert]]:
    """Group chronologically-sorted alerts into time-proximity clusters.

    Alerts more than `window` apart from the previous alert start a new cluster.
    """
    if not sorted_alerts:
        return []

    clusters: list[list[Alert]] = [[sorted_alerts[0]]]

    for alert in sorted_alerts[1:]:
        last_alert_in_cluster = clusters[-1][-1]
        if alert.timestamp - last_alert_in_cluster.timestamp <= window:
            clusters[-1].append(alert)
        else:
            clusters.append([alert])

    return clusters
