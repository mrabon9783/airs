from datetime import datetime, timedelta, timezone

from src.Shared.scanner import classify_expiry, classify_stale


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def dt(days: int) -> str:
    return (NOW + timedelta(days=days)).isoformat().replace("+00:00", "Z")


def test_expiry_thresholds():
    assert classify_expiry(dt(-1), now=NOW).status == "expired"
    assert classify_expiry(dt(7), now=NOW).status == "expiring_7"
    assert classify_expiry(dt(30), now=NOW).status == "expiring_30"
    assert classify_expiry(dt(90), now=NOW).status == "expiring_90"
    assert classify_expiry(dt(91), now=NOW).status == "healthy"


def test_stale_thresholds():
    assert classify_stale(None, threshold_days=90, now=NOW) == "never_used"
    assert classify_stale(dt(-120), threshold_days=90, now=NOW) == "stale"
    assert classify_stale(dt(-10), threshold_days=90, now=NOW) == "active"
