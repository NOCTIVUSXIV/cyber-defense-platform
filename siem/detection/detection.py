
from datetime import datetime  # Provides timestamp handling.


# Check whether an event represents a failed SSH authentication.
def is_failed_ssh(event):
    message = (event.get("message") or "").lower()
    process = (event.get("process") or "").lower()

    ssh_process = process.startswith("sshd")
    ssh_message = "sshd" in message

    pam_failure = (
        "authentication failure" in message
        and (ssh_process or ssh_message)
    )

    password_failure = (
        "failed password" in message
        and (ssh_process or ssh_message)
    )

    return pam_failure or password_failure


# Check whether an event represents a failed sudo authentication.
def is_failed_sudo(event):
    message = (event.get("message") or "").lower()
    process = (event.get("process") or "").lower()

    sudo_event = "sudo" in message or process == "sudo"

    return (
        sudo_event
        and "authentication failure" in message
    )


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
    if is_failed_sudo(event):
        return {
            "rule": "FAILED_SUDO_AUTHENTICATION",
            "severity": "HIGH",
            "message": event.get("message"),
            "hostname": event.get("hostname"),
            "process": event.get("process"),
            "event_timestamp": event.get("timestamp"),
        }

    return None


# Detect a failed SSH authentication attempt.
def detect_failed_ssh(event):
    if is_failed_ssh(event):
        return {
            "rule": "FAILED_SSH_AUTHENTICATION",
            "severity": "HIGH",
            "message": event.get("message"),
            "hostname": event.get("hostname"),
            "process": event.get("process"),
            "event_timestamp": event.get("timestamp"),
        }

    return None


# Detect three or more failed sudo authentications within five minutes.
def detect_repeated_failed_sudo(event_history):
    failed_events = []

    for event in event_history:
        timestamp = event.get("timestamp")

        if not is_failed_sudo(event) or not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(timestamp)

        except (TypeError, ValueError):
            continue

        failed_events.append((event_time, event))

    if len(failed_events) < 3:
        return None

    latest_time, latest_event = failed_events[-1]

    recent_failures = [
        event
        for event_time, event in failed_events
        if 0 <= (latest_time - event_time).total_seconds() <= 300
    ]

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


# Detect three or more failed SSH authentications within five minutes.
def detect_repeated_failed_ssh(event_history):
    failed_events = []

    for event in event_history:
        timestamp = event.get("timestamp")

        if not is_failed_ssh(event) or not timestamp:
            continue

        try:
            event_time = datetime.fromisoformat(timestamp)

        except (TypeError, ValueError):
            continue

        failed_events.append((event_time, event))

    if len(failed_events) < 3:
        return None

    latest_time, latest_event = failed_events[-1]

    recent_failures = [
        event
        for event_time, event in failed_events
        if 0 <= (latest_time - event_time).total_seconds() <= 300
    ]

    if len(recent_failures) >= 3:
        return {
            "rule": "REPEATED_FAILED_SSH",
            "severity": "CRITICAL",
            "message": f"{len(recent_failures)} failed SSH authentication attempts within 5 minutes",
            "hostname": latest_event.get("hostname"),
            "process": latest_event.get("process"),
            "event_timestamp": latest_event.get("timestamp"),
        }

    return None


# List single-event detection rules.
DETECTION_RULES = [
    detect_high_priority,
    detect_failed_sudo,
    detect_failed_ssh,
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

    sudo_alert = detect_repeated_failed_sudo(event_history)

    if sudo_alert is not None:
        alerts.append(sudo_alert)

    ssh_alert = detect_repeated_failed_ssh(event_history)

    if ssh_alert is not None:
        alerts.append(ssh_alert)

    return alerts


# Test the detection engine when this file is executed directly.
if __name__ == "__main__":
    test_events = [
        {
            "timestamp": "2026-09-17T00:00:00+00:00",
            "severity": "5",
            "message": "pam_unix(sshd:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sshd-session",
        },
        {
            "timestamp": "2026-09-17T00:02:00+00:00",
            "severity": "5",
            "message": "pam_unix(sshd:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sshd-session",
        },
        {
            "timestamp": "2026-09-17T00:04:00+00:00",
            "severity": "5",
            "message": "pam_unix(sshd:auth): authentication failure",
            "hostname": "pranav-arch",
            "process": "sshd-session",
        },
    ]

    print("Single-event detections:")

    for event in test_events:
        print(detect_event(event))

    print("\nCorrelation detections:")
    print(detect_correlations(test_events))
