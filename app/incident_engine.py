def create_incidents(alerts, correlations):
    incidents = []

    for correlation in correlations:
        related_alerts = [
            alert
            for alert in alerts
            if alert["event"]["source_ip"] == correlation["source_ip"]
        ]

        if not related_alerts:
            continue

        events = [
            alert["event"]
            for alert in related_alerts
        ]

        timestamps = [
            event["timestamp"]
            for event in events
        ]

        risk_scores = [
            alert["risk"]["risk_score"]
            for alert in related_alerts
        ]

        incidents.append({
            "incident_id": f"INC-{len(incidents) + 1:04d}",
            "type": correlation["type"],
            "source_ip": correlation["source_ip"],
            "username": events[0]["username"],
            "related_events": len(events),
            "risk_score": max(risk_scores),
            "risk_level": max(
                related_alerts,
                key=lambda alert: alert["risk"]["risk_score"]
            )["risk"]["risk_level"],
            "status": "open",
            "timeline": timestamps,
            "evidence": {
                "correlation_id": correlation["correlation_id"],
                "event_count": correlation["event_count"],
                "time_window_seconds": correlation["time_window_seconds"],
                "reason": correlation["reason"]
            }
        })

    return incidents


if __name__ == "__main__":
    test_alerts = [
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

    test_correlations = [
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

    result = create_incidents(
        test_alerts,
        test_correlations
    )

    print(result)
