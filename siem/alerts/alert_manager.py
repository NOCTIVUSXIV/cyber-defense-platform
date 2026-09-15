from datetime import datetime, timezone  # Provides UTC alert timestamps.
from siem.database.database import insert_alert  # Imports the database alert function.


# Create and store a structured alert from a detection result.
def create_alert(detection):
    # Record when the SIEM creates the alert.
    alert_timestamp = datetime.now(timezone.utc).isoformat()

    alert = {
        "event_timestamp": detection.get("event_timestamp"),
        "alert_timestamp": alert_timestamp,
        "rule": detection.get("rule"),
        "severity": detection.get("severity"),
        "message": detection.get("message"),
        "hostname": detection.get("hostname"),
        "process": detection.get("process"),
    }

    insert_alert(alert)

    return alert