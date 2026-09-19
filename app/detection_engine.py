from app.log_parser import parse_log


def detect_event(event):
    if event["event_type"] == "authentication_failure":
        return {
            "rule_id": "AUTH-001",
            "alert": True,
            "severity": "medium",
            "reason": "Authentication failure detected",
            "evidence": {
                "username": event["username"],
                "source_ip": event["source_ip"],
                "timestamp": event["timestamp"]
            }
        }

    return {
        "rule_id": None,
        "alert": False,
        "severity": "none",
        "reason": "No detection rule matched",
        "evidence": {}
    }


if __name__ == "__main__":
    test_log = (
        "2026-09-19 07:31:12 WARNING "
        "Failed login username=admin ip=192.168.1.20"
    )

    parsed_event = parse_log(test_log)

    if parsed_event:
        result = detect_event(parsed_event)
        print(result)
    else:
        print("Could not parse log.")
