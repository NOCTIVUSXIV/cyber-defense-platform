from siem.database.database import insert_alert  # Imports the database alert function.


# Create and store a structured alert from a detection result.
def create_alert(detection):
    alert = {
        "rule": detection.get("rule"),
        "severity": detection.get("severity"),
        "message": detection.get("message"),
        "hostname": detection.get("hostname"),
        "process": detection.get("process"),
    }

    insert_alert(alert)

    return alert