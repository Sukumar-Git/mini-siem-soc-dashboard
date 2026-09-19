from datetime import datetime


def correlate_events(events):
    correlations = []

    failed_events = [
        event
        for event in events
        if event["event_type"] == "authentication_failure"
    ]

    ip_groups = {}

    for event in failed_events:
        ip = event["source_ip"]

        if ip not in ip_groups:
            ip_groups[ip] = []

        ip_groups[ip].append(event)

    for ip, ip_events in ip_groups.items():
        ip_events.sort(key=lambda event: event["timestamp"])

        for i in range(len(ip_events)):
            window_events = []

            start_time = datetime.strptime(
                ip_events[i]["timestamp"],
                "%Y-%m-%d %H:%M:%S"
            )

            for event in ip_events[i:]:
                event_time = datetime.strptime(
                    event["timestamp"],
                    "%Y-%m-%d %H:%M:%S"
                )

                difference = (event_time - start_time).total_seconds()

                if difference <= 60:
                    window_events.append(event)
                else:
                    break

            if len(window_events) >= 3:
                correlations.append({
                    "correlation_id": "AUTH-CORR-001",
                    "type": "possible_brute_force",
                    "source_ip": ip,
                    "event_count": len(window_events),
                    "time_window_seconds": 60,
                    "reason": (
                        "Multiple authentication failures from the "
                        "same source IP within 60 seconds"
                    )
                })

                break

    return correlations


if __name__ == "__main__":
    test_events = [
        {
            "timestamp": "2026-09-19 07:31:12",
            "level": "WARNING",
            "event": "Failed login",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.20"
        },
        {
            "timestamp": "2026-09-19 07:31:15",
            "level": "WARNING",
            "event": "Failed login",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.20"
        },
        {
            "timestamp": "2026-09-19 07:31:18",
            "level": "WARNING",
            "event": "Failed login",
            "event_type": "authentication_failure",
            "username": "admin",
            "source_ip": "192.168.1.20"
        }
    ]

    result = correlate_events(test_events)

    print(result)
