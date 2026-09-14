from collector.collector import collect_events  # Imports the log collector.
from parser.parser import parse_event  # Imports the event parser.
from database.database import create_database, insert_event  # Imports database functions.


def process_events():
    # Make sure the database and events table exist.
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

        # Confirm that the event reached the database.
        print("Event stored successfully.")


# Start the SIEM pipeline when this file is executed directly.
if __name__ == "__main__":
    process_events()