NETWORK_RULES = {
    "NET-001": {
        "name": "Suspicious Network Connection",
        "description": (
            "Detects a network connection event that "
            "may require investigation."
        ),
        "event_type": "suspicious_network_connection",
        "severity": "medium"
    },

    "NET-002": {
        "name": "Suspicious Destination",
        "description": (
            "Detects a connection attempt to a destination "
            "that has been identified as suspicious."
        ),
        "event_type": "suspicious_destination",
        "severity": "high"
    }
}