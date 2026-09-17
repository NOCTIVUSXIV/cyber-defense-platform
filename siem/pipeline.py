from collections import deque  # Provides a fixed-size event history.
from siem.collector.collector import collect_events  # Imports the log collector.
from siem.parser.parser import parse_event  # Imports the event parser.
from siem.database.database import create_database, insert_event  # Imports database functions.
from siem.detection.detection import detect_event, detect_correlations  # Imports detection functions.
from siem.alerts.alert_manager import create_alert  # Imports the alert manager.


HISTORY_SIZE = 100  # Keeps the latest 100 events available for correlation.


def process_events():
    # Make sure the database and tables exist.
    create_database()

    # Keep recent events in memory for correlation.
    event_history = deque(maxlen=HISTORY_SIZE)

    # Continuously receive raw events from the collector.
    for raw_event in collect_events():
        # Convert the raw JSON event into a normalized event.
        parsed_event = parse_event(raw_event)

        # Skip the event if parsing failed.
        if parsed_event is None:
            continue

        # Add the event to the recent event history.
        event_history.append(parsed_event)

        # Store the normalized event in the database.
        insert_event(parsed_event)

        # Run single-event detection rules.
        detections = detect_event(parsed_event)

        # Create and store an alert for every single-event detection.
        for detection in detections:
            alert = create_alert(detection)
            print(f"ALERT: {alert}")

        # Run correlation rules against recent events.
        correlations = detect_correlations(event_history)

        # Create and store an alert for every correlation detection.
        for correlation in correlations:
            alert = create_alert(correlation)
            print(f"CORRELATION ALERT: {alert}")

        # Confirm that the event reached the database.
        print("Event stored successfully.")


# Start the SIEM pipeline when this file is executed directly.
if __name__ == "__main__":
    process_events()