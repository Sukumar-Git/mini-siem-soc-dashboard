import re
from datetime import datetime


LOG_PATTERN = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2}) "
    r"(?P<time>\d{2}:\d{2}:\d{2}) "
    r"(?P<level>[A-Z]+) "
    r"(?P<message>.*?)"
    r"(?:\s+username=(?P<username>\S+))?"
    r"(?:\s+ip=(?P<source_ip>\S+))?$"
)


def classify_event(message):
    message_lower = message.lower()

    if "failed login" in message_lower:
        return "authentication_failure"

    if "login successful" in message_lower:
        return "authentication_success"

    return "unknown"


def parse_log(log_line):
    log_line = log_line.strip()

    if not log_line:
        return None

    match = LOG_PATTERN.match(log_line)

    if not match:
        return None

    timestamp = f"{match.group('date')} {match.group('time')}"
    level = match.group("level")
    message = match.group("message").strip()
    username = match.group("username")
    source_ip = match.group("source_ip")

    try:
        datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    event_type = classify_event(message)

    return {
        "timestamp": timestamp,
        "level": level,
        "event": message,
        "event_type": event_type,
        "username": username,
        "source_ip": source_ip
    }


if __name__ == "__main__":
    test_log = (
        "2026-09-19 07:31:12 WARNING "
        "Failed login username=admin ip=192.168.1.20"
    )

    parsed_event = parse_log(test_log)

    print(parsed_event)
