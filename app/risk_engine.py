def calculate_risk(event, detection):
    score = 0
    factors = []

    if detection["alert"]:
        score += 20
        factors.append({
            "points": 20,
            "reason": "Detection rule matched"
        })

    if event["event_type"] == "authentication_failure":
        score += 10
        factors.append({
            "points": 10,
            "reason": "Authentication failure"
        })

    if event["level"] == "WARNING":
        score += 10
        factors.append({
            "points": 10,
            "reason": "Warning-level event"
        })

    if score >= 70:
        risk_level = "critical"
    elif score >= 50:
        risk_level = "high"
    elif score >= 30:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "factors": factors
    }


if __name__ == "__main__":
    test_event = {
        "timestamp": "2026-09-19 07:31:12",
        "level": "WARNING",
        "event": "Failed login",
        "event_type": "authentication_failure",
        "username": "admin",
        "source_ip": "192.168.1.20"
    }

    test_detection = {
        "rule_id": "AUTH-001",
        "alert": True,
        "severity": "medium",
        "reason": "Authentication failure detected",
        "evidence": {
            "username": "admin",
            "source_ip": "192.168.1.20",
            "timestamp": "2026-09-19 07:31:12"
        }
    }

    result = calculate_risk(test_event, test_detection)

    print(result)
