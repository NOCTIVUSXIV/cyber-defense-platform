from parser.parser import parse_event  # Imports the parser function.
from database.database import create_database, insert_event  # Imports database functions.


def process_event(raw_event):
    # Convert the raw JSON event into a normalized event.
    parsed_event = parse_event(raw_event)

    # Stop processing if the parser rejected the event.
    if parsed_event is None:
        return

    # Store the normalized event in the database.
    insert_event(parsed_event)

    print("Event stored successfully.")


# Test the pipeline when this file is executed directly.
if __name__ == "__main__":
    create_database()

    test_event = '{"MESSAGE":"SIEM pipeline test","PRIORITY":"5","_PID":"50000","_HOSTNAME":"pranav-arch","_COMM":"pipeline","SYSLOG_IDENTIFIER":"siem","__REALTIME_TIMESTAMP":"1789306812868670"}'

    process_event(test_event)