// ── Clock ──
function tick() {
    document.getElementById('clock').textContent =
      new Date().toLocaleTimeString('en-GB', { hour12: false });
}
tick(); 
setInterval(tick, 1000);

let lastLogId = 0;
let lastAlertId = 0;

document.addEventListener('DOMContentLoaded', () => {
    // Look at the first row rendered by Jinja to find the newest ID
    const latestLog = document.querySelector('#log-stream-tbody tr');
    const latestAlert = document.querySelector('#alerts-tbody tr');

    if (latestLog && latestLog.dataset.id) {
        lastLogId = parseInt(latestLog.dataset.id);
    }
    if (latestAlert && latestAlert.dataset.id) {
        lastAlertId = parseInt(latestAlert.dataset.id);
    }
    
    console.log(`Initialized: LogID ${lastLogId}, AlertID ${lastAlertId}`);
    
    // Start the 5-second loop
    setInterval(updateDashboard, 5000);
});

async function updateDashboard() {
    try {
        // --- FETCH PACKET LOGS ---
        const logRes = await fetch(`/api/logs?last_id=${lastLogId}`);
        const logData = await logRes.json();

        if (logData.logs.length > 0) {
            const logTbody = document.getElementById('log-stream-tbody');
            
            // Update the global last_id to the newest one in the list
            // Since we sorted by ASC in subsequent loads, the last one is newest
            const newLogs = logData.logs;
            lastLogId = Math.max(...newLogs.map(l => l.id), lastLogId);

            newLogs.reverse().forEach(log => {
                const row = `
                <tr class="new-row">
                    <td>${log.timestamp}</td>
                    <td>${log.src_ip}</td>
                    <td>${log.dst_ip}</td>
                    <td style="color:var(--accent2)">${log.hostname}</td>
                    <td><span class="badge">${log.protocol}</span></td>
                    <td>${log.ports}</td>
                    <td>${log.size}</td>
                </tr>`;
                logTbody.insertAdjacentHTML('afterbegin', row);
            });

        }

        // --- FETCH SECURITY INCIDENTS ---

        const incRes = await fetch(`/api/incidents?last_id=${lastAlertId}`);
        const incDataAll = await incRes.json();
        const incData = incDataAll.data;

        if (incData.length > 0) {
            const alertTbody = document.getElementById('alerts-tbody');
            lastAlertId = Math.max(...incData.map(i => i.id), lastAlertId);

            incData.reverse().forEach(inc => {
                // Remove the "No alerts" empty message if it exists
                const emptyMsg = alertTbody.querySelector('.empty');
                if (emptyMsg) alertTbody.innerHTML = '';

                const row = `
                <tr class="alert-row">
                    <td>${inc.timestamp}</td>
                    <td>${inc.src_ip}</td>
                    <td>${inc.dst_ip}</td>
                    <td><b style="color:var(--danger)">${inc.type}</b></td>
                    <td>${inc.desc}</td>
                </tr>`;
                alertTbody.insertAdjacentHTML('afterbegin', row);
            });
        }

        // Update Stat Cards
        document.getElementById('stat-total').innerText = Number(document.getElementById('stat-total').innerText) + logData.total_logs;
        document.getElementById('stat-alerts').innerText = Number(document.getElementById('stat-alerts').innerText) + incDataAll.total_alerts;
    
        
    } catch (err) {
        console.error("Dashboard Update Error:", err);
    }
}

// Start Cycle
setInterval(updateDashboard, 5000); // 5 seconds as requested
updateDashboard();
