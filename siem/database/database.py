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
            rule TEXT,
            severity TEXT,
            message TEXT,
            hostname TEXT,
            process TEXT
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

    # Insert the alert into the alerts table.
    cursor.execute("""
        INSERT INTO alerts (
            rule,
            severity,
            message,
            hostname,
            process
        )
        VALUES (?, ?, ?, ?, ?)
    """, (
        alert.get("rule"),
        alert.get("severity"),
        alert.get("message"),
        alert.get("hostname"),
        alert.get("process"),
    ))

    # Save the inserted alert.
    connection.commit()

    # Close the database connection.
    connection.close()


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