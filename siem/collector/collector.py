import subprocess  # Allows Python to start and communicate with journalctl.


# Command used to follow new events from the systemd journal.
JOURNAL_COMMAND = [
    "journalctl",
    "-f",
    "-o",
    "json",
]


def collect_events():
    try:
        # Start journalctl as a child process.
        process = subprocess.Popen(
            JOURNAL_COMMAND,
            stdout=subprocess.PIPE,  # Sends journalctl output into Python.
            text=True,  # Makes the output available as strings.
        )

    except FileNotFoundError:
        # Handle the case where journalctl is not installed.
        print("Error: journalctl was not found.")
        return

    except PermissionError:
        # Handle the case where access to the journal is denied.
        print("Error: permission denied while accessing the journal.")
        return

    except OSError as error:
        # Handle other operating-system errors.
        print(f"Error starting journalctl: {error}")
        return

    try:
        # Continuously read events produced by journalctl.
        for line in process.stdout:
            print(line.strip())  # Display the raw event for testing.

        # Check whether journalctl stopped unexpectedly.
        if process.poll() is not None:
            print("Error: journalctl stopped unexpectedly.")

    except KeyboardInterrupt:
        # Handle Ctrl+C so the collector can shut down cleanly.
        print("\nCollector stopping...")

    finally:
        # Terminate journalctl if it is still running.
        if process.poll() is None:
            process.terminate()


# Start the collector when this file is executed directly.
if __name__ == "__main__":
    collect_events()