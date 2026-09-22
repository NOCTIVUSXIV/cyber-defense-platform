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


def insert_alert(alert):
    # Open the SIEM database.
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


def get_recent_events(limit=50):
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Return database rows using column names.
    connection.row_factory = sqlite3.Row

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Retrieve the most recent events.
    cursor.execute("""
        SELECT *
        FROM events
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    # Convert database rows into dictionaries.
    events = [dict(event) for event in cursor.fetchall()]

    # Close the database connection.
    connection.close()

    return events


def get_recent_alerts(limit=50):
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Return database rows using column names.
    connection.row_factory = sqlite3.Row

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Retrieve the most recent alerts.
    cursor.execute("""
        SELECT *
        FROM alerts
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))

    # Convert database rows into dictionaries.
    alerts = [dict(alert) for alert in cursor.fetchall()]

    # Close the database connection.
    connection.close()

    return alerts


def get_alerts_by_severity(severity, limit=50):
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Return database rows using column names.
    connection.row_factory = sqlite3.Row

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Retrieve alerts matching the requested severity.
    cursor.execute("""
        SELECT *
        FROM alerts
        WHERE severity = ?
        ORDER BY id DESC
        LIMIT ?
    """, (severity, limit))

    # Convert database rows into dictionaries.
    alerts = [dict(alert) for alert in cursor.fetchall()]

    # Close the database connection.
    connection.close()

    return alerts


def get_event_counts():
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Count events grouped by severity.
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM events
        GROUP BY severity
        ORDER BY COUNT(*) DESC
    """)

    # Convert database results into dictionaries.
    counts = [
        {
            "severity": row[0],
            "count": row[1],
        }
        for row in cursor.fetchall()
    ]

    # Close the database connection.
    connection.close()

    return counts


def get_alert_counts():
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Count alerts grouped by severity.
    cursor.execute("""
        SELECT severity, COUNT(*)
        FROM alerts
        GROUP BY severity
        ORDER BY COUNT(*) DESC
    """)

    # Convert database results into dictionaries.
    counts = [
        {
            "severity": row[0],
            "count": row[1],
        }
        for row in cursor.fetchall()
    ]

    # Close the database connection.
    connection.close()

    return counts


def get_event_activity():
    # Open the SIEM database.
    connection = sqlite3.connect(DATABASE_PATH)

    # Create a cursor for executing SQL commands.
    cursor = connection.cursor()

    # Generate every hour from the last 24 hours.
    cursor.execute("""
        WITH RECURSIVE hours(hour) AS (
            SELECT strftime(
                '%Y-%m-%d %H:00:00',
                'now',
                '-23 hours'
            )

            UNION ALL

            SELECT strftime(
                '%Y-%m-%d %H:00:00',
                datetime(hour, '+1 hour')
            )
            FROM hours
            WHERE hour < strftime(
                '%Y-%m-%d %H:00:00',
                'now'
            )
        )

        SELECT
            hours.hour,
            COUNT(events.id) AS count
        FROM hours
        LEFT JOIN events
            ON strftime(
                '%Y-%m-%d %H:00:00',
                events.timestamp
            ) = hours.hour
        GROUP BY hours.hour
        ORDER BY hours.hour ASC
    """)

    # Convert database results into dictionaries.
    activity = [
        {
            "hour": row[0],
            "count": row[1],
        }
        for row in cursor.fetchall()
    ]

    # Close the database connection.
    connection.close()

    return activity


# Test database functions when this file is executed directly.
if __name__ == "__main__":
    create_database()

    print(f"Recent events: {len(get_recent_events())}")
    print(f"Recent alerts: {len(get_recent_alerts())}")
    print(f"High alerts: {len(get_alerts_by_severity('HIGH'))}")
    print(f"Event counts: {get_event_counts()}")
    print(f"Alert counts: {get_alert_counts()}")
    print(f"Event activity: {get_event_activity()}")