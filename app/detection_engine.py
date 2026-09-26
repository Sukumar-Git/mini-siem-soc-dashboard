from app.log_parser import parse_log
from rules.auth_rules import AUTH_RULES
from rules.network_rules import NETWORK_RULES


def detect_event(event):
    """
    Evaluate a parsed security event against detection rules.
    """

    # --------------------------------------------------
    # AUTH-001: Authentication failure
    # --------------------------------------------------

    if event["event_type"] == AUTH_RULES["AUTH-001"]["event_type"]:

        rule = AUTH_RULES["AUTH-001"]

        return {
            "rule_id": "AUTH-001",
            "alert": True,
            "severity": rule["severity"],
            "reason": rule["description"],
            "evidence": {
                "username": event["username"],
                "source_ip": event["source_ip"],
                "timestamp": event["timestamp"]
            }
        }


    # --------------------------------------------------
    # NET-001: Suspicious network connection
    # --------------------------------------------------

    if (
        event["event_type"]
        == NETWORK_RULES["NET-001"]["event_type"]
    ):

        rule = NETWORK_RULES["NET-001"]

        return {
            "rule_id": "NET-001",
            "alert": True,
            "severity": rule["severity"],
            "reason": rule["description"],
            "evidence": {
                "source_ip": event["source_ip"],
                "timestamp": event["timestamp"]
            }
        }


    # --------------------------------------------------
    # NET-002: Suspicious destination
    # --------------------------------------------------

    if (
        event["event_type"]
        == NETWORK_RULES["NET-002"]["event_type"]
    ):

        rule = NETWORK_RULES["NET-002"]

        return {
            "rule_id": "NET-002",
            "alert": True,
            "severity": rule["severity"],
            "reason": rule["description"],
            "evidence": {
                "source_ip": event["source_ip"],
                "timestamp": event["timestamp"]
            }
        }


    # --------------------------------------------------
    # No rule matched
    # --------------------------------------------------

    return {
        "rule_id": None,
        "alert": False,
        "severity": "none",
        "reason": "No detection rule matched",
        "evidence": {}
    }


if __name__ == "__main__":

    test_logs = [

        (
            "2026-09-19 07:31:12 WARNING "
            "Failed login username=admin ip=192.168.1.20"
        ),

        (
            "2026-09-19 07:35:00 WARNING "
            "Suspicious network connection ip=10.0.0.25"
        ),

        (
            "2026-09-19 07:40:12 WARNING "
            "Connection to suspicious destination "
            "ip=185.220.101.5"
        )
    ]


    for test_log in test_logs:

        parsed_event = parse_log(test_log)

        if parsed_event:

            result = detect_event(parsed_event)

            print(result)

        else:

            print("Could not parse log.")