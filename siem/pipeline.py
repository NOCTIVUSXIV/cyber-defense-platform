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
        parsed_event = parse_event(raw_event)

        if parsed_event is None:
            continue

        event_history.append(parsed_event)
        insert_event(parsed_event)

        detections = detect_event(parsed_event)

        for detection in detections:
            alert = create_alert(detection)

            if alert is not None:
                print(f"ALERT CREATED: {alert}")
            else:
                print("ALERT SUPPRESSED: duplicate within cooldown.")

        correlations = detect_correlations(event_history)

        for correlation in correlations:
            alert = create_alert(correlation)

            if alert is not None:
                print(f"CORRELATION ALERT CREATED: {alert}")
            else:
                print("CORRELATION ALERT SUPPRESSED: duplicate within cooldown.")

        print("Event stored successfully.")


if __name__ == "__main__":
    process_events()