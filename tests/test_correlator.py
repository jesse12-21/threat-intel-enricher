"""Tests for alert correlation logic."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from enricher.correlator import correlate_by_attacker
from enricher.models import Alert


def _make_alert(ts: datetime, src_ip: str, sig: str = "Test Alert") -> Alert:
    return Alert(
        id=f"a-{ts.isoformat()}",
        timestamp=ts,
        signature=sig,
        severity=2,
        category="Test",
        src_ip=src_ip,
        dest_ip="10.0.0.1",
    )


class TestCorrelateByAttacker:
    def test_empty_input(self) -> None:
        assert correlate_by_attacker([]) == []

    def test_isolated_alerts_filtered(self) -> None:
        """Single alerts with no related activity are skipped."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = [_make_alert(base, "1.2.3.4")]
        campaigns = correlate_by_attacker(alerts, min_campaign_size=2)
        assert campaigns == []

    def test_groups_same_ip_within_window(self) -> None:
        """Alerts from same IP within time window form one campaign."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = [
            _make_alert(base, "1.2.3.4"),
            _make_alert(base + timedelta(minutes=2), "1.2.3.4"),
            _make_alert(base + timedelta(minutes=5), "1.2.3.4"),
        ]
        campaigns = correlate_by_attacker(alerts, time_window_minutes=15)
        assert len(campaigns) == 1
        assert campaigns[0].attacker_ip == "1.2.3.4"
        assert campaigns[0].alert_count == 3

    def test_splits_across_windows(self) -> None:
        """Alerts from same IP separated by > window form separate campaigns."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = [
            _make_alert(base, "1.2.3.4"),
            _make_alert(base + timedelta(minutes=2), "1.2.3.4"),
            # Gap of 20 minutes — new campaign
            _make_alert(base + timedelta(minutes=25), "1.2.3.4"),
            _make_alert(base + timedelta(minutes=26), "1.2.3.4"),
        ]
        campaigns = correlate_by_attacker(alerts, time_window_minutes=15)
        assert len(campaigns) == 2

    def test_separates_different_ips(self) -> None:
        """Alerts from different source IPs are separate campaigns."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = [
            _make_alert(base, "1.2.3.4"),
            _make_alert(base + timedelta(minutes=1), "1.2.3.4"),
            _make_alert(base, "5.6.7.8"),
            _make_alert(base + timedelta(minutes=1), "5.6.7.8"),
        ]
        campaigns = correlate_by_attacker(alerts)
        assert len(campaigns) == 2
        ips = {c.attacker_ip for c in campaigns}
        assert ips == {"1.2.3.4", "5.6.7.8"}

    def test_sorted_by_alert_count(self) -> None:
        """Largest campaigns come first — most aggressive attacker surfaces to top."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = []
        # Small campaign from 5.6.7.8 (3 alerts)
        for i in range(3):
            alerts.append(_make_alert(base + timedelta(seconds=i * 10), "5.6.7.8"))
        # Large campaign from 1.2.3.4 (8 alerts)
        for i in range(8):
            alerts.append(_make_alert(base + timedelta(seconds=i * 10), "1.2.3.4"))

        campaigns = correlate_by_attacker(alerts)
        assert len(campaigns) == 2
        assert campaigns[0].attacker_ip == "1.2.3.4"
        assert campaigns[0].alert_count == 8

    def test_top_signature_extracted(self) -> None:
        """Top signature should be the most common across the campaign."""
        base = datetime(2026, 4, 1, 12, 0, 0, tzinfo=UTC)
        alerts = [
            _make_alert(base, "1.2.3.4", "SQL Injection"),
            _make_alert(base + timedelta(seconds=30), "1.2.3.4", "SQL Injection"),
            _make_alert(base + timedelta(minutes=1), "1.2.3.4", "Path Traversal"),
        ]
        campaigns = correlate_by_attacker(alerts)
        assert len(campaigns) == 1
        assert campaigns[0].top_signature == "SQL Injection"
        assert set(campaigns[0].signatures) == {"SQL Injection", "Path Traversal"}
