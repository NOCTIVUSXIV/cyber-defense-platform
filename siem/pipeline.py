from siem.collector.collector import collect_events  # Imports the log collector.
from siem.parser.parser import parse_event  # Imports the event parser.
from siem.database.database import create_database, insert_event  # Imports database functions.
from siem.detection.detection import detect_event  # Imports the detection engine.
from siem.alerts.alert_manager import create_alert  # Imports the alert manager.


def process_events():
    # Make sure the database and tables exist.
    create_database()

    # Continuously receive raw events from the collector.
    for raw_event in collect_events():
        # Convert the raw JSON event into a normalized event.
        parsed_event = parse_event(raw_event)

        # Skip the event if parsing failed.
        if parsed_event is None:
            continue

        # Store the normalized event in the database.
        insert_event(parsed_event)

        # Run all detection rules against the event.
        detections = detect_event(parsed_event)

        # Create and store an alert for every detection.
        for detection in detections:
            alert = create_alert(detection)
            print(f"ALERT: {alert}")

        # Confirm that the event reached the database.
        print("Event stored successfully.")


# Start the SIEM pipeline when this file is executed directly.
if __name__ == "__main__":
    process_events()