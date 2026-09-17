import sqlite3  # Provides SQLite database functionality.


DATABASE_PATH = "siem/database/siem.db"  # Defines where the SIEM database is stored.


def create_database():
    # Open the SQLite database or create it if it does not exist.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Create the events table if it does not already exist.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            hostname TEXT,
            process TEXT,
            pid TEXT,
            severity TEXT,
            message TEXT,
            source TEXT
        )
    """)

    # Create the alerts table if it does not already exist.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_timestamp TEXT,
            alert_timestamp TEXT,
            rule TEXT,
            severity TEXT,
            message TEXT,
            hostname TEXT,
            process TEXT,
            fingerprint TEXT
        )
    """)

    # Save the database changes.
    connection.commit()

    # Close the database connection.
    connection.close()


def insert_event(event):
    # Open the existing SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Insert the normalized event into the database.
    cursor.execute("""
        INSERT INTO events (
            timestamp,
            hostname,
            process,
            pid,
            severity,
            message,
            source
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("timestamp"),
        event.get("hostname"),
        event.get("process"),
        event.get("pid"),
        event.get("severity"),
        event.get("message"),
        event.get("source"),
    ))

    # Save the inserted event.
    connection.commit()

    # Close the database connection.
    connection.close()


# Store a detected alert in the database.
def insert_alert(alert):
    # Open the existing SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Insert the alert and its metadata into the database.
    cursor.execute("""
        INSERT INTO alerts (
            event_timestamp,
            alert_timestamp,
            rule,
            severity,
            message,
            hostname,
            process,
            fingerprint
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert.get("event_timestamp"),
        alert.get("alert_timestamp"),
        alert.get("rule"),
        alert.get("severity"),
        alert.get("message"),
        alert.get("hostname"),
        alert.get("process"),
        alert.get("fingerprint"),
    ))

    # Save the inserted alert.
    connection.commit()

    # Close the database connection.
    connection.close()


# Check whether the same alert was created recently.
def recent_alert_exists(fingerprint, cooldown_seconds=300):
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Find a matching fingerprint within the cooldown period.
    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE fingerprint = ?
        AND (
            strftime('%s', 'now') -
            strftime('%s', alert_timestamp)
        ) <= ?
        LIMIT 1
    """, (fingerprint, cooldown_seconds))

    # Get the matching alert if one exists.
    result = cursor.fetchone()

    # Close the database connection.
    connection.close()

    return result is not None


def get_events():
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Return database rows using column names.
    connection.row_factory = sqlite3.Row

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Retrieve all stored events.
    cursor.execute("SELECT * FROM events")

    # Store the returned database rows.
    events = cursor.fetchall()

    # Convert SQLite rows into normal Python dictionaries.
    events = [dict(event) for event in events]

    # Close the database connection.
    connection.close()

    return events


# Test database functions when this file is executed directly.
if __name__ == "__main__":
    create_database()

    events = get_events()

    print(f"Stored events: {len(events)}")

    for event in events:
        print(event)