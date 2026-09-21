from app.risk_engine import calculate_risk


def test_authentication_failure_risk():
    event = {
        "event_type": "authentication_failure",
        "level": "WARNING"
    }

    detection = {
        "alert": True
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 40
    assert result["risk_level"] == "medium"


def test_network_event_risk():
    event = {
        "event_type": "suspicious_network_connection",
        "level": "WARNING"
    }

    detection = {
        "alert": True
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 30
    assert result["risk_level"] == "medium"


def test_no_alert_low_risk():
    event = {
        "event_type": "authentication_success",
        "level": "INFO"
    }

    detection = {
        "alert": False
    }

    result = calculate_risk(event, detection)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "low"
