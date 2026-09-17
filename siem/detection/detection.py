from datetime import datetime  # Provides timestamp handling.


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


# Detect a failed sudo authentication attempt.
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


# Detect three or more failed sudo authentications within five minutes.
def detect_repeated_failed_sudo(event_history):
    failed_events = []

    for event in event_history:
        message = event.get("message")
        timestamp = event.get("timestamp")

        if message and "authentication failure" in message.lower():
            if timestamp:
                try:
                    event_time = datetime.fromisoformat(timestamp)

                except ValueError:
                    continue

                failed_events.append((event_time, event))

    if len(failed_events) < 3:
        return None

    latest_time, latest_event = failed_events[-1]

    recent_failures = []

    for event_time, event in failed_events:
        time_difference = latest_time - event_time

        if 0 <= time_difference.total_seconds() <= 300:
            recent_failures.append(event)

    if len(recent_failures) >= 3:
        return {
            "rule": "REPEATED_FAILED_SUDO",
            "severity": "CRITICAL",
            "message": f"{len(recent_failures)} failed sudo authentication attempts within 5 minutes",
            "hostname": latest_event.get("hostname"),
            "process": latest_event.get("process"),
            "event_timestamp": latest_event.get("timestamp"),
        }

    return None


# List single-event detection rules.
DETECTION_RULES = [
    detect_high_priority,
    detect_failed_sudo,
]


# Run single-event detection rules against an event.
def detect_event(event):
    alerts = []

    for rule in DETECTION_RULES:
        alert = rule(event)

        if alert is not None:
            alerts.append(alert)

    return alerts


# Run history-based correlation rules against multiple events.
def detect_correlations(event_history):
    alerts = []

    alert = detect_repeated_failed_sudo(event_history)

    if alert is not None:
        alerts.append(alert)

    return alerts


# Test the detection engine when this file is executed directly.
if __name__ == "__main__":
    test_events = [
        {
            "timestamp": "2026-09-17T00:00:00+00:00",
            "severity": "5",
            "message": "pam_unix(sudo:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sudo",
        },
        {
            "timestamp": "2026-09-17T00:02:00+00:00",
            "severity": "5",
            "message": "pam_unix(sudo:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sudo",
        },
        {
            "timestamp": "2026-09-17T00:04:00+00:00",
            "severity": "5",
            "message": "pam_unix(sudo:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sudo",
        },
    ]

    alerts = detect_correlations(test_events)

    print(alerts)