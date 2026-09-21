async function loadStatistics() {
    // Request statistics from the SIEM API.
    const response = await fetch(
        "http://127.0.0.1:8000/statistics"
    );

    // Convert the API response into JavaScript data.
    const data = await response.json();

    // Calculate the total number of events.
    const totalEvents = data.events.reduce(
        (total, item) => total + item.count,
        0
    );

    // Calculate the total number of alerts.
    const totalAlerts = data.alerts.reduce(
        (total, item) => total + item.count,
        0
    );

    // Find the number of critical alerts.
    const criticalAlerts = data.alerts.find(
        item => item.severity === "CRITICAL"
    );

    // Display the statistics.
    document.getElementById("event-count").textContent =
        totalEvents;

    document.getElementById("alert-count").textContent =
        totalAlerts;

    document.getElementById("critical-count").textContent =
        criticalAlerts ? criticalAlerts.count : 0;
}


async function loadAlerts() {
    // Request recent alerts from the SIEM API.
    const response = await fetch(
        "http://127.0.0.1:8000/alerts"
    );

    // Convert the API response into JavaScript data.
    const alerts = await response.json();

    // Find the dashboard alert table.
    const container = document.getElementById(
        "alerts-container"
    );

    // Clear the loading message.
    container.innerHTML = "";

    // Display the latest 10 alerts.
    alerts.slice(0, 10).forEach(alert => {
        const row = document.createElement("tr");

        // Convert the severity into a CSS class.
        const severityClass =
            alert.severity.toLowerCase();

        // Add alert information to the table.
        row.innerHTML = `
            <td>
                <span class="severity severity-${severityClass}">
                    ${alert.severity}
                </span>
            </td>

            <td class="rule">
                ${alert.rule}
            </td>

            <td class="message">
                ${alert.message}
            </td>

            <td class="metadata">
                ${alert.hostname || "-"}
            </td>

            <td class="metadata">
                ${alert.process || "-"}
            </td>

            <td class="metadata">
                ${alert.event_timestamp || "-"}
            </td>
        `;

        // Add the row to the alert table.
        container.appendChild(row);
    });
}


// Load SIEM statistics when the page opens.
loadStatistics();

// Load recent alerts when the page opens.
loadAlerts();