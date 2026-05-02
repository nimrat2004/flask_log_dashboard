// ── Clock ──
function tick() {
    const clockEl = document.getElementById('clock');
    if (clockEl) {
        clockEl.textContent = new Date().toLocaleTimeString('en-GB', { hour12: false });
    }
}
tick();
setInterval(tick, 1000);

// ── State ──
let lastLogId = 0;
let lastAlertId = 0;
let isUpdating = false;   // prevent overlapping fetches

document.addEventListener('DOMContentLoaded', () => {
    // Read the HIGHEST id from ALL rendered rows — not just the first one
    const allLogRows = document.querySelectorAll('#log-stream-tbody tr[data-id]');
    const allAlertRows = document.querySelectorAll('#alerts-tbody tr[data-id]');

    allLogRows.forEach(row => {
        const id = parseInt(row.dataset.id);
        if (id > lastLogId) lastLogId = id;
    });

    allAlertRows.forEach(row => {
        const id = parseInt(row.dataset.id);
        if (id > lastAlertId) lastAlertId = id;
    });

    console.log(`Initialized: LogID=${lastLogId}, AlertID=${lastAlertId}`);

    updateDashboard();
    loadDashboard();
    setInterval(loadDashboard, 5000);
});



// ── DOM row limit — keeps browser fast ──
const MAX_LOG_ROWS = 200;
const MAX_ALERT_ROWS = 100;

function trimRows(tbodyId, maxRows) {
    const tbody = document.getElementById(tbodyId);
    if (!tbody) return;
    const rows = tbody.querySelectorAll('tr');
    if (rows.length > maxRows) {
        // Remove oldest rows from the bottom
        for (let i = maxRows; i < rows.length; i++) {
            rows[i].remove();
        }
    }
}

async function loadDashboard() {
    try {
    const res = await fetch("/api/dashboard");
    if (!res.ok) throw new Error("API error");

    const data = await res.json();

    updateLineChart(data);
    updateScatterChart(data);

} catch (err) {
    console.error("Dashboard Load Error:", err);
}
}


async function updateDashboard() {
    // Skip this cycle if previous fetch is still running
    if (isUpdating) {
        setTimeout(updateDashboard, 4000);
        return;
    }

    isUpdating = true;

    try {
        // ── 1. Fetch packet logs ──────────────────────────────────────
        const logRes = await fetch(`/api/logs?last_id=${lastLogId}`);
        if (!logRes.ok) throw new Error(`Logs fetch failed: ${logRes.status}`);
        const logData = await logRes.json();

        if (logData.logs && logData.logs.length > 0) {
            const logTbody = document.getElementById('log-stream-tbody');

            // Update lastLogId to highest received
            lastLogId = Math.max(...logData.logs.map(l => l.id), lastLogId);
            
            let logHtml = "";
            logData.logs.reverse().forEach(log => {
                console.log(log.timestamp)
                logHtml += `
                <tr class="new-row" data-id="${log.id}">
                    <td>${log.timestamp}</td>
                    <td>${log.src_ip}</td>
                    <td>${log.dst_ip}</td>
                    <td style="color:var(--accent2)">${log.hostname}</td>
                    <td><span class="badge">${log.protocol}</span></td>
                    <td>${log.ports}</td>
                    <td>${log.size}</td>
                </tr>`;
            });

            logTbody.insertAdjacentHTML('afterbegin', logHtml);
            trimRows('log-stream-tbody', MAX_LOG_ROWS);   // ← keep DOM lean
        }

        // Set stat card to TRUE total — not increment
        if (logData.total_logs !== undefined) {
            const el = document.getElementById('stat-total');
            if (el) el.innerText = logData.total_logs;
        }


        // ── 2. Fetch incidents ────────────────────────────────────────
        const incRes = await fetch(`/api/incidents?last_id=${lastAlertId}`);
        if (!incRes.ok) throw new Error(`Incidents fetch failed: ${incRes.status}`);
        const incDataAll = await incRes.json();
        const incData = incDataAll.data || [];

        if (incData.length > 0) {
            const alertTbody = document.getElementById('alerts-tbody');

            lastAlertId = Math.max(...incData.map(i => i.id), lastAlertId);

            // Remove empty placeholder only once
            const emptyMsg = alertTbody.querySelector('.empty, .empty-row');
            if (emptyMsg) emptyMsg.remove();

            let incHtml = "";
            incData.reverse().forEach(inc => {
                const rowClass = inc.type === "BruteForce"
                    ? "alert-row alert-bruteforce"
                    : "alert-row";

                incHtml += `
                <tr class="${rowClass}" data-id="${inc.id}">
                    <td>${inc.timestamp}</td>
                    <td>${inc.src_ip}</td>
                    <td>${inc.dst_ip}</td>
                    <td><b style="color:var(--danger)">${inc.type}</b></td>
                    <td>${inc.desc}</td>
                </tr>`;
            });

            alertTbody.insertAdjacentHTML('afterbegin', incHtml);
            trimRows('alerts-tbody', MAX_ALERT_ROWS);     // ← keep DOM lean
        }

        // Set alert card to TRUE total
        if (incDataAll.total_alerts !== undefined) {
            const el = document.getElementById('stat-alerts');
            if (el) el.innerText = incDataAll.total_alerts;
        }

    } catch (err) {
        console.error("Dashboard Update Error:", err);
    } finally {
        isUpdating = false;
        setTimeout(updateDashboard, 4000);   // next cycle
     
    }
}

let lineChart;

function updateLineChart(data) {
    const ctx = document.getElementById("lineChart").getContext("2d");

    if (lineChart) lineChart.destroy();

    lineChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: data.timestamps,
            datasets: [{
                label: "Packet Size",
                data: data.packet_sizes,
                borderWidth: 2
            }]
        }
    });
}

let scatterChart;

function updateScatterChart(data) {
    const ctx = document.getElementById("scatterChart").getContext("2d");

    if (scatterChart) scatterChart.destroy();

    const points = data.scatter_x.map((x, i) => ({
        x: x,
        y: data.scatter_y[i],
        backgroundColor: data.anomaly[i] === -1 ? "red" : "blue"
    }));

    scatterChart = new Chart(ctx, {
        type: "scatter",
        data: {
            datasets: [{
                label: "Traffic Behavior",
                data: points,
                pointRadius: 5
            }]
        },
        options: {
            scales: {
                x: { title: { display: true, text: "Packet Size" }},
                y: { title: { display: true, text: "Destination Port" }}
            }
        }
    });
}

