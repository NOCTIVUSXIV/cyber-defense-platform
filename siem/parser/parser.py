import json  # Provides tools for reading JSON data.
from datetime import datetime, timezone  # Provides timestamp conversion.


def parse_event(raw_event):
    try:
        # Convert the JSON text into a Python dictionary.
        event = json.loads(raw_event)

    except json.JSONDecodeError:
        # Reject events that are not valid JSON.
        print("Error: received invalid JSON.")
        return None

    timestamp = event.get("__REALTIME_TIMESTAMP")

    if timestamp is not None:
        try:
            # Convert journal microseconds into a UTC timestamp.
            timestamp = datetime.fromtimestamp(
                int(timestamp) / 1_000_000,
                tz=timezone.utc,
            ).isoformat()

        except (TypeError, ValueError, OSError):
            # Reject timestamps that cannot be converted.
            timestamp = None

    # Build a normalized event for the rest of the SIEM.
    normalized_event = {
        "timestamp": timestamp,
        "hostname": event.get("_HOSTNAME"),
        "process": event.get("_COMM"),
        "pid": event.get("_PID"),
        "severity": event.get("PRIORITY"),
        "message": event.get("MESSAGE"),
        "source": event.get("SYSLOG_IDENTIFIER"),
    }

    return normalized_event


# Test the parser when this file is executed directly.
if __name__ == "__main__":
    test_event = '{"MESSAGE":"SIEM timestamp test","PRIORITY":"5","_PID":"47681","_HOSTNAME":"pranav-arch","_COMM":"logger","SYSLOG_IDENTIFIER":"pranav","__REALTIME_TIMESTAMP":"1789306812868670"}'

    parsed_event = parse_event(test_event)

    print(parsed_event)