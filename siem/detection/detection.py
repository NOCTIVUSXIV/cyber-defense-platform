# Detect events with a high system priority.
def detect_high_priority(event):
    severity = event.get("severity")

    if severity is None:
        return None

    try:
        severity = int(severity)

    except (TypeError, ValueError):
        return None

    if severity <= 2:
        return {
            "rule": "HIGH_PRIORITY_EVENT",
            "severity": "HIGH",
            "message": event.get("message"),
            "hostname": event.get("hostname"),
            "process": event.get("process"),
            "event_timestamp": event.get("timestamp"),
        }

    return None


# Detect failed sudo authentication attempts.
def detect_failed_sudo(event):
    message = event.get("message")

    if message is None:
        return None

    if "authentication failure" in message.lower():
        return {
            "rule": "FAILED_SUDO_AUTHENTICATION",
            "severity": "HIGH",
            "message": message,
            "hostname": event.get("hostname"),
            "process": event.get("process"),
            "event_timestamp": event.get("timestamp"),
        }

    return None


# List all detection rules used by the engine.
DETECTION_RULES = [
    detect_high_priority,
    detect_failed_sudo,
]


# Run every detection rule against an event.
def detect_event(event):
    alerts = []

    for rule in DETECTION_RULES:
        alert = rule(event)

        if alert is not None:
            alerts.append(alert)

    return alerts


# Test the detection engine when this file is executed directly.
if __name__ == "__main__":
    test_event = {
        "timestamp": "2026-09-15T06:46:13.978399+00:00",
        "severity": "5",
        "message": "pam_unix(sudo:auth): authentication failure",
        "hostname": "pranav-arch",
        "process": "sudo",
    }

    alerts = detect_event(test_event)

    print(alerts)