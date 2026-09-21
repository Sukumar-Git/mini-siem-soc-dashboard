from app.detection_engine import detect_event


def test_authentication_failure_detection():
    event = {
        "timestamp": "2026-09-19 07:31:12",
        "level": "WARNING",
        "event": "Failed login",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "192.168.1.20"
    }

    result = detect_event(event)

    assert result["alert"] is True
    assert result["rule_id"] == "AUTH-001"
    assert result["severity"] == "medium"


def test_network_detection():
    event = {
        "timestamp": "2026-09-19 07:35:00",
        "level": "WARNING",
        "event": "Suspicious network connection",
        "event_type": "suspicious_network_connection",
        "username": None,
        "source_ip": "10.0.0.25"
    }

    result = detect_event(event)

    assert result["alert"] is True
    assert result["rule_id"] == "NET-001"
    assert result["severity"] == "medium"


def test_successful_login_no_alert():
    event = {
        "timestamp": "2026-09-19 07:30:01",
        "level": "INFO",
        "event": "User login successful",
        "event_type": "authentication_success",
        "username": "sukumar",
        "source_ip": "192.168.1.10"
    }

    result = detect_event(event)

    assert result["alert"] is False
    assert result["rule_id"] is None
