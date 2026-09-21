from app.correlation_engine import correlate_events


def test_brute_force_correlation():
    events = [
        {
            "timestamp": "2026-09-19 07:31:12",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.20"
        },
        {
            "timestamp": "2026-09-19 07:31:15",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.20"
        },
        {
            "timestamp": "2026-09-19 07:31:18",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.20"
        }
    ]

    result = correlate_events(events)

    assert len(result) == 1
    assert result[0]["correlation_id"] == "AUTH-CORR-001"
    assert result[0]["source_ip"] == "192.168.1.20"
    assert result[0]["event_count"] == 3


def test_no_correlation_for_single_failure():
    events = [
        {
            "timestamp": "2026-09-19 07:31:12",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.20"
        }
    ]

    result = correlate_events(events)

    assert result == []


def test_no_correlation_for_different_ips():
    events = [
        {
            "timestamp": "2026-09-19 07:31:12",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.20"
        },
        {
            "timestamp": "2026-09-19 07:31:15",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.30"
        },
        {
            "timestamp": "2026-09-19 07:31:18",
            "event_type": "authentication_failure",
            "source_ip": "192.168.1.40"
        }
    ]

    result = correlate_events(events)

    assert result == []
