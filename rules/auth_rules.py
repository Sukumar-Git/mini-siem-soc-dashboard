AUTH_RULES = {
    "AUTH-001": {
        "name": "Authentication Failure",
        "description": "Detects a failed authentication attempt.",
        "event_type": "authentication_failure",
        "severity": "medium"
    },

    "AUTH-002": {
        "name": "Possible Brute Force",
        "description": (
            "Identifies a possible brute-force pattern when "
            "multiple authentication failures occur from "
            "the same source."
        ),
        "event_type": "authentication_failure",
        "severity": "high"
    }
}
