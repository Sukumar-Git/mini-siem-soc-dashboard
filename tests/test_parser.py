from app.log_parser import parse_log


def test_parse_failed_login():
    log = (
        "2026-09-19 07:31:12 WARNING "
        "Failed login username=admin ip=192.168.1.20"
    )

    event = parse_log(log)

    assert event is not None
    assert event["event_type"] == "authentication_failure"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.168.1.20"


def test_parse_successful_login():
    log = (
        "2026-09-19 07:30:01 INFO "
        "User login successful username=sukumar ip=192.168.1.10"
    )

    event = parse_log(log)

    assert event is not None
    assert event["event_type"] == "authentication_success"


def test_parse_invalid_log():
    log = "this is not a valid security log"

    event = parse_log(log)

    assert event is None


def test_parse_network_event():
    log = (
        "2026-09-19 07:35:00 WARNING "
        "Suspicious network connection ip=10.0.0.25"
    )

    event = parse_log(log)

    assert event is not None
    assert event["event_type"] == "suspicious_network_connection"
    assert event["source_ip"] == "10.0.0.25"
