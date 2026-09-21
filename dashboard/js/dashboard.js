// Load event and alert statistics from the SIEM API.
async function loadStatistics() {

    try {

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


        // Find the number of high-severity alerts.
        const highAlerts = data.alerts.find(
            item => item.severity === "HIGH"
        );


        // Display the total number of events.
        document.getElementById("event-count").textContent =
            totalEvents;


        // Display the total number of alerts.
        document.getElementById("alert-count").textContent =
            totalAlerts;


        // Display the critical count in the main statistics card.
        document.getElementById("critical-count").textContent =
            criticalAlerts ? criticalAlerts.count : 0;


        // Display the critical count in the severity section.
        document.getElementById("critical-alert-count").textContent =
            criticalAlerts ? criticalAlerts.count : 0;


        // Display the high count in the severity section.
        document.getElementById("high-alert-count").textContent =
            highAlerts ? highAlerts.count : 0;

    } catch (error) {

        // Log an error if the API cannot be reached.
        console.error("Failed to load statistics:", error);

    }
}


// Convert an ISO timestamp into a readable UTC timestamp.
function formatTimestamp(timestamp) {

    // Return a placeholder when no timestamp exists.
    if (!timestamp) {
        return "-";
    }


    // Convert the timestamp into a JavaScript Date object.
    const date = new Date(timestamp);


    // Format the timestamp using UTC and 24-hour time.
    const formattedTimestamp = date.toLocaleString("en-AU", {
        timeZone: "UTC",
        day: "2-digit",
        month: "short",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false
    });


    // Explicitly show the UTC zero offset.
    return `${formattedTimestamp} UTC+00:00`;
}


// Load recent security alerts from the SIEM API.
async function loadAlerts() {

    try {

        // Request recent alerts from the SIEM API.
        const response = await fetch(
            "http://127.0.0.1:8000/alerts"
        );


        // Convert the API response into JavaScript data.
        const alerts = await response.json();


        // Find the dashboard alert table body.
        const container = document.getElementById(
            "alerts-container"
        );


        // Remove the loading message.
        container.innerHTML = "";


        // Display the latest 10 alerts.
        alerts.slice(0, 10).forEach(alert => {

            // Create a new table row.
            const row = document.createElement("tr");


            // Convert the severity into lowercase for the CSS class.
            const severityClass =
                alert.severity.toLowerCase();


            // Add the alert information to the table.
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
                    ${formatTimestamp(alert.event_timestamp)}
                </td>

            `;


            // Add the completed row to the alert table.
            container.appendChild(row);

        });

    } catch (error) {

        // Log an error if the API cannot be reached.
        console.error("Failed to load alerts:", error);

    }
}


// Load SIEM statistics when the dashboard opens.
loadStatistics();


// Load recent SIEM alerts when the dashboard opens.
loadAlerts();