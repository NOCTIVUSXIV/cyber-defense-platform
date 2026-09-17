import hashlib  # Provides hashing for alert fingerprints.
from datetime import datetime, timezone  # Provides UTC alert timestamps.
from siem.database.database import insert_alert, recent_alert_exists  # Imports alert storage and cooldown checking.


# Create a consistent fingerprint for similar alerts.
def generate_fingerprint(detection):
    # Combine important alert fields into one string.
    fingerprint_data = "|".join([
        str(detection.get("rule")),
        str(detection.get("hostname")),
        str(detection.get("process")),
        str(detection.get("message")),
    ])

    # Generate a SHA-256 fingerprint from the alert data.
    return hashlib.sha256(
        fingerprint_data.encode("utf-8")
    ).hexdigest()


# Create and store a structured alert from a detection result.
def create_alert(detection):
    # Record when the SIEM creates the alert.
    alert_timestamp = datetime.now(timezone.utc).isoformat()

    # Generate a unique fingerprint for this alert pattern.
    fingerprint = generate_fingerprint(detection)

    # Suppress the alert if the same fingerprint was recently stored.
    if recent_alert_exists(fingerprint):
        return None

    alert = {
        "event_timestamp": detection.get("event_timestamp"),
        "alert_timestamp": alert_timestamp,
        "rule": detection.get("rule"),
        "severity": detection.get("severity"),
        "message": detection.get("message"),
        "hostname": detection.get("hostname"),
        "process": detection.get("process"),
        "fingerprint": fingerprint,
    }

    # Store the new alert in the database.
    insert_alert(alert)

    return alert