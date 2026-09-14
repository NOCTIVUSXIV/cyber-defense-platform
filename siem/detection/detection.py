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
        }

    return None


# List all detection rules used by the engine.
DETECTION_RULES = [
    detect_high_priority,
]


# Run every detection rule against an event.
def detect_event(event):
    alerts = []

    for rule in DETECTION_RULES:
        alert = rule(event)

        if alert is not None:
            alerts.append(alert)

    return alerts