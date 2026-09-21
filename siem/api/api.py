from fastapi import FastAPI  # Imports the FastAPI framework.
from fastapi.middleware.cors import CORSMiddleware  # Allows the dashboard to access the API.
from siem.database.database import (  # Imports SIEM database query functions.
    get_recent_events,
    get_recent_alerts,
    get_event_counts,
    get_alert_counts,
)


app = FastAPI(title="Cyber Defense Platform API")  # Creates the API application.


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    # Confirm that the API is running.
    return {"message": "Cyber Defense Platform API is running"}


@app.get("/events")
def events():
    # Retrieve recent events from the SIEM database.
    return get_recent_events()


@app.get("/alerts")
def alerts():
    # Retrieve recent alerts from the SIEM database.
    return get_recent_alerts()


@app.get("/statistics")
def statistics():
    # Retrieve event and alert statistics for the dashboard.
    return {
        "events": get_event_counts(),
        "alerts": get_alert_counts(),
    }