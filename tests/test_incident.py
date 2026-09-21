from app.incident_engine import create_incidents


def test_incident_creation():
    alerts = [
        {
            "event": {
                "timestamp": "2026-09-19 07:31:12",
                "username": "admin",
                "source_ip": "192.168.1.20"
            },
            "risk": {
                "risk_score": 40,
                "risk_level": "medium"
            }
        },
        {
            "event": {
                "timestamp": "2026-09-19 07:31:15",
                "username": "admin",
                "source_ip": "192.168.1.20"
            },
            "risk": {
                "risk_score": 40,
                "risk_level": "medium"
            }
        },
        {
            "event": {
                "timestamp": "2026-09-19 07:31:18",
                "username": "admin",
                "source_ip": "192.168.1.20"
            },
            "risk": {
                "risk_score": 40,
                "risk_level": "medium"
            }
        }
    ]

    correlations = [
        {
            "correlation_id": "AUTH-CORR-001",
            "type": "possible_brute_force",
            "source_ip": "192.168.1.20",
            "event_count": 3,
            "time_window_seconds": 60,
            "reason": (
                "Multiple authentication failures from the "
                "same source IP within 60 seconds"
            )
        }
    ]

    result = create_incidents(alerts, correlations)

    assert len(result) == 1
    assert result[0]["incident_id"] == "INC-0001"
    assert result[0]["source_ip"] == "192.168.1.20"
    assert result[0]["username"] == "admin"
    assert result[0]["related_events"] == 3
    assert result[0]["risk_score"] == 40
    assert result[0]["risk_level"] == "medium"
    assert result[0]["status"] == "open"


def test_no_incident_without_correlation():
    alerts = [
        {
            "event": {
                "timestamp": "2026-09-19 07:31:12",
                "username": "admin",
                "source_ip": "192.168.1.20"
            },
            "risk": {
                "risk_score": 40,
                "risk_level": "medium"
            }
        }
    ]

    result = create_incidents(alerts, [])

    assert result == []
