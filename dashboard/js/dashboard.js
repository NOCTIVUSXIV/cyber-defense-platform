// Store the latest alerts so the search feature can reuse them.
let currentAlerts = [];


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


        // Extract the critical count.
        const criticalCount =
            criticalAlerts ? criticalAlerts.count : 0;


        // Extract the high count.
        const highCount =
            highAlerts ? highAlerts.count : 0;


        // Display the total event count.
        document.getElementById("event-count").textContent =
            totalEvents.toLocaleString();


        // Display the total alert count.
        document.getElementById("alert-count").textContent =
            totalAlerts.toLocaleString();


        // Display the critical count.
        document.getElementById("critical-count").textContent =
            criticalCount;


        // Display the high count.
        document.getElementById("high-count").textContent =
            highCount;


        // Display the critical count in the severity panel.
        document.getElementById("critical-alert-count").textContent =
            criticalCount;


        // Display the high count in the severity panel.
        document.getElementById("high-alert-count").textContent =
            highCount;


        // Display the total alert count in the severity panel.
        document.getElementById("severity-total").textContent =
            totalAlerts;


        // Display the alert count in the sidebar.
        document.getElementById("sidebar-alert-count").textContent =
            totalAlerts;


        // Calculate the largest severity value.
        const maximumSeverity =
            Math.max(criticalCount, highCount, 1);


        // Calculate the critical bar width.
        const criticalWidth =
            (criticalCount / maximumSeverity) * 100;


        // Calculate the high bar width.
        const highWidth =
            (highCount / maximumSeverity) * 100;


        // Update the critical severity bar.
        document.getElementById("critical-bar").style.width =
            `${criticalWidth}%`;


        // Update the high severity bar.
        document.getElementById("high-bar").style.width =
            `${highWidth}%`;

    } catch (error) {

        // Log an error if the API cannot be reached.
        console.error(
            "Failed to load statistics:",
            error
        );

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
    const formattedTimestamp = date.toLocaleString(
        "en-AU",
        {
            timeZone: "UTC",
            day: "2-digit",
            month: "short",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit",
            second: "2-digit",
            hour12: false
        }
    );


    // Explicitly show the UTC zero offset.
    return `${formattedTimestamp} UTC+00:00`;
}


// Display alerts inside the dashboard table.
function renderAlerts(alerts) {

    // Find the alert table body.
    const container =
        document.getElementById("alerts-container");


    // Clear the current table contents.
    container.innerHTML = "";


    // Show an empty state when no alerts match.
    if (alerts.length === 0) {

        container.innerHTML = `
            <tr>
                <td colspan="6" class="empty-state">
                    No matching alerts found.
                </td>
            </tr>
        `;

        return;
    }


    // Display the latest 10 alerts.
    alerts.slice(0, 10).forEach(alert => {

        // Create a table row.
        const row =
            document.createElement("tr");


        // Convert severity to lowercase for the CSS class.
        const severityClass =
            String(alert.severity).toLowerCase();


        // Add the alert information to the table.
        row.innerHTML = `

            <td>
                <span class="severity severity-${severityClass}">
                    ${alert.severity}
                </span>
            </td>

            <td class="rule">
                ${alert.rule || "-"}
            </td>

            <td class="message">
                ${alert.message || "-"}
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


        // Add the row to the alert table.
        container.appendChild(row);

    });
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


        // Store alerts for the search feature.
        currentAlerts = alerts;


        // Display the alerts.
        renderAlerts(currentAlerts);


        // Update detection activity.
        renderDetectionActivity(currentAlerts);

    } catch (error) {

        // Log an error if the API cannot be reached.
        console.error(
            "Failed to load alerts:",
            error
        );

    }
}


// Display detection rules ranked by alert count.
function renderDetectionActivity(alerts) {

    // Store alert counts for each rule.
    const ruleCounts = {};


    // Count alerts generated by each rule.
    alerts.forEach(alert => {

        // Use the rule name or a fallback.
        const rule =
            alert.rule || "UNKNOWN_RULE";


        // Create the counter if it doesn't exist.
        if (!ruleCounts[rule]) {
            ruleCounts[rule] = 0;
        }


        // Increase the rule count.
        ruleCounts[rule] += 1;

    });


    // Convert the object into an array and sort by count.
    const rules =
        Object.entries(ruleCounts)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);


    // Find the detection activity container.
    const container =
        document.getElementById("detection-list");


    // Clear the existing detection list.
    container.innerHTML = "";


    // Show an empty state if there are no detections.
    if (rules.length === 0) {

        container.innerHTML = `
            <div class="loading-small">
                No detection activity available.
            </div>
        `;

        return;
    }


    // Find the largest rule count.
    const maximumCount =
        Math.max(...rules.map(rule => rule[1]), 1);


    // Create a row for each detection rule.
    rules.forEach(([rule, count]) => {

        // Calculate the visual bar width.
        const width =
            (count / maximumCount) * 100;


        // Create a detection row.
        const item =
            document.createElement("div");


        // Apply the detection row styling.
        item.className = "detection-item";


        // Add the detection information.
        item.innerHTML = `

            <span class="detection-name">
                ${rule}
            </span>

            <div class="detection-bar">

                <div
                    class="detection-bar-fill"
                    style="width: ${width}%"
                ></div>

            </div>

            <span class="detection-count">
                ${count}
            </span>

        `;


        // Add the detection row to the dashboard.
        container.appendChild(item);

    });
}


// Search alerts using the search field.
function searchAlerts() {

    // Get the search input.
    const searchInput =
        document.getElementById("alert-search");


    // Convert the search text to lowercase.
    const searchTerm =
        searchInput.value.toLowerCase().trim();


    // Show all alerts if the search is empty.
    if (!searchTerm) {

        renderAlerts(currentAlerts);

        return;
    }


    // Search through multiple alert fields.
    const filteredAlerts =
        currentAlerts.filter(alert => {

            // Combine searchable alert fields.
            const searchableText = [

                alert.severity,
                alert.rule,
                alert.message,
                alert.hostname,
                alert.process

            ]
                .filter(Boolean)
                .join(" ")
                .toLowerCase();


            // Return alerts containing the search term.
            return searchableText.includes(
                searchTerm
            );

        });


    // Display the filtered alerts.
    renderAlerts(filteredAlerts);
}


// Update the dashboard UTC clock.
function updateClock() {

    // Create a Date object representing the current time.
    const now = new Date();


    // Format the current time in UTC.
    const time =
        now.toLocaleTimeString(
            "en-AU",
            {
                timeZone: "UTC",
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
                hour12: false
            }
        );


    // Display the current UTC time.
    document.getElementById(
        "current-time"
    ).textContent = time;


    // Display the last dashboard update time.
    document.getElementById(
        "last-update"
    ).textContent =
        `Updated ${time} UTC`;

}


// Refresh all dashboard data.
async function refreshDashboard() {

    // Load the latest statistics.
    await loadStatistics();


    // Load the latest alerts.
    await loadAlerts();


    // Update the dashboard clock.
    updateClock();

}


// Listen for changes in the alert search box.
document.getElementById(
    "alert-search"
).addEventListener(
    "input",
    searchAlerts
);


// Load dashboard data when the page opens.
refreshDashboard();


// Update the UTC clock every second.
setInterval(
    updateClock,
    1000
);


// Refresh SIEM data every 10 seconds.
setInterval(
    refreshDashboard,
    10000
);