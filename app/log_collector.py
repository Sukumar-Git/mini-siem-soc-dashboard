from pathlib import Path


LOG_FILE = Path("logs/sample.log")


def collect_logs():
    """Read and return all lines from the log file."""
    if not LOG_FILE.exists():
        print(f"Log file not found: {LOG_FILE}")
        return []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        return file.readlines()


if __name__ == "__main__":
    logs = collect_logs()

    print(f"Collected {len(logs)} log entries:\n")

    for log in logs:
        print(log.strip())
