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
let chart;
let labels = [], vals = [], peak = 0, sum = 0;
let lastW = 0, scrollPending = false;

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
    initLineChart();
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
async function loadDashboard() {
    try {
    const res = await fetch("/api/dashboard");
    if (!res.ok) throw new Error("API error");
   

    const data = await res.json();
     console.log(data)
    updateLineChart(data);
    updateScatterChart(data);

} catch (err) {
    console.error("Dashboard Load Error:", err);
}
}
// function updateLineChart(data) {
//     const canvas = document.getElementById("lineChart");

//     const totalPoints = lineChart.data.labels.length + data.timestamps.length;

//     // 🔥 FIX: use STYLE width (not only canvas.width)
//     canvas.style.width = (totalPoints * 8) + "px";

//     data.timestamps.forEach((t, i) => {
//         lineChart.data.labels.push(t);
//         lineChart.data.datasets[0].data.push(data.packet_sizes[i]);
//     });
    
//     lineChart.update();
// }

// let lineChart;

// function initLineChart() {
//     const ctx = document.getElementById("lineChart").getContext("2d");

//     lineChart = new Chart(ctx, {
//     type: "line",
//     data: {
//         labels: [],
//         datasets: [{
//             label: "Packet Size",
//             data: [],
//             borderWidth: 2
//         }]
//     },
//     options: {
//         responsive: true,        // 🔥 IMPORTANT
//         maintainAspectRatio: false,
//         animation: false,
//         scales: {
//             x: {
//                 ticks: {
//                     autoSkip: true   // prevents crowding
//                 }
//             }
//         }
//     }
// });
// }

function initLineChart() {
     
    const canvas = document.getElementById('lineChart');
    const sw = document.getElementById('sw');

if (!sw) return false;
const wrapW = sw.getBoundingClientRect().width || 600;
    const w = Math.max(wrapW, 50 * 18);
    canvas.style.width  = w + 'px';
    canvas.style.height = '280px';
    canvas.width  = Math.round(w * (window.devicePixelRatio || 1));
    canvas.height = Math.round(280 * (window.devicePixelRatio || 1));
    lastW = w;

    const isDark = matchMedia('(prefers-color-scheme:dark)').matches;
    const gc = isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.05)';
    const tc = isDark ? '#999' : '#888';

    chart = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
            labels : allLabels,
            datasets: [
                {
                    label: 'Packet size',
                    data: allData,
                    borderColor: '#378add',
                    backgroundColor: 'rgba(55,138,221,.07)',
                    borderWidth: 1.5,
                    pointRadius: 2.5,
                    pointHoverRadius: 5,
                    pointBackgroundColor: '#378add',
                    tension: 0.3,
                    fill: true,
                    order: 2
                },
                {
                    label: 'Moving avg',
                    data: [],
                    borderColor: '#1d9e75',
                    borderWidth: 1.5,
                    borderDash: [4, 3],
                    pointRadius: 0,
                    tension: 0.4,
                    fill: false,
                    order: 1
                }
            ]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            animation: false,
            plugins: { legend: { display: false }, tooltip: { enabled: false } },
            scales: {
                x: { grid: { color: gc }, ticks: { color: tc, font: { size: 11 }, autoSkip: true, maxTicksLimit: 18, maxRotation: 40 } },
                y: { grid: { color: gc }, ticks: { color: tc, font: { size: 11 } }, title: { display: true, text: 'Bytes', color: tc, font: { size: 11 } } }
            }
        }
    });
    console.log('chart created:', chart); 
}

const PX_PER_POINT = 18;   // px per data point — never changes
const DPR = window.devicePixelRatio || 1;  // fixes blurry canvas on retina
const CHART_HEIGHT = 300;

let allLabels = [];
let allData = [];

function resizeCanvas(n) {
    const sw = document.getElementById('sw');
    if (!sw) return false;
    const cw = document.getElementById('cw');
    if (!cw) return false;

    const wrapW = sw.getBoundingClientRect().width || 600;  // ✅ use sw directly
    const w = Math.max(wrapW, n * PX_PER_POINT);
    const canvas = document.getElementById('lineChart');

    cw.style.width = w + 'px';                        // ✅ use cw directly
    canvas.style.width  = w + 'px';
    canvas.style.height = CHART_HEIGHT + 'px';
    canvas.width  = Math.round(w * DPR);
    canvas.height = Math.round(CHART_HEIGHT * DPR);

    return true;
}

function updateLineChart(data) {
if (!chart) return; 
  data.timestamps.forEach((t, i) => {
    allLabels.push(t);
    allData.push(data.packet_sizes[i]);
  });

  resizeCanvas(allLabels.length);   // grows right, never shrinks
    chart.data.labels = allLabels;
    chart.data.datasets[0].data = allData;
    chart.data.datasets[1].data = movingAvg(allData);
    chart.update('none');
    chart.resize();
  
}

function movingAvg(arr, w = 5) {
  return arr.map((_, i) => {
    const s = arr.slice(Math.max(0, i - w + 1), i + 1);
    return +(s.reduce((a, b) => a + b, 0) / s.length).toFixed(1);
  });
}


let scatterChart;

// Separate color per dataset — clusters are visually distinct
const CLUSTER_COLORS = {
    0: { border: '#378add', bg: 'rgba(55,138,221,0.55)' },   // blue — cluster 0
    1: { border: '#1d9e75', bg: 'rgba(29,158,117,0.55)' },   // green — cluster 1
    2: { border: '#ba7517', bg: 'rgba(186,117,23,0.55)' },   // amber — cluster 2
};
const ANOMALY_COLOR = { border: '#e24b4a', bg: 'rgba(226,75,74,0.7)' };

function buildScatterDatasets(data) {
    // Separate points into buckets by cluster/anomaly — NO destroy/recreate
    const buckets = {};  // key: 'anomaly' | '0' | '1' | '2'...

    data.scatter_x.forEach((x, i) => {
        const isAnomaly = data.anomaly[i] === -1;
        const key = isAnomaly ? 'anomaly' : String(data.cluster[i]);
        if (!buckets[key]) buckets[key] = [];
        buckets[key].push({ x, y: data.scatter_y[i] });
    });

    const datasets = [];

    // Anomalies first so they render on top
    if (buckets['anomaly']) {
        datasets.push({
            label: 'Anomaly',
            data: buckets['anomaly'],
            pointBackgroundColor: ANOMALY_COLOR.bg,
            pointBorderColor: ANOMALY_COLOR.border,
            pointBorderWidth: 1.5,
            pointRadius: 5,
            pointStyle: 'triangle',   // different shape = not just color
        });
    }

    // One dataset per cluster
    Object.keys(buckets).filter(k => k !== 'anomaly').sort().forEach(key => {
        const c = CLUSTER_COLORS[key] || { border: '#888780', bg: 'rgba(136,135,128,0.5)' };
        datasets.push({
            label: `Cluster ${key}`,
            data: buckets[key],
            pointBackgroundColor: c.bg,
            pointBorderColor: c.border,
            pointBorderWidth: 1,
            pointRadius: 4,
            pointStyle: 'circle',
        });
    });

    return datasets;
}

function updateScatterChart(data) {
    if (!data?.scatter_x?.length) return;

    const isDark = matchMedia('(prefers-color-scheme:dark)').matches;
    const gc = isDark ? 'rgba(255,255,255,.06)' : 'rgba(0,0,0,.05)';
    const tc = isDark ? '#999' : '#888';

    const datasets = buildScatterDatasets(data);

    if (!scatterChart) {
        // ✅ Create ONCE — never destroy
        const ctx = document.getElementById('scatterChart').getContext('2d');
        scatterChart = new Chart(ctx, {
            type: 'scatter',
            data: { datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,           // no jump, instant update
                plugins: {
                    legend: { display: false },   // we use custom legend below
                    tooltip: {
                        callbacks: {
                            label: ctx => `(${ctx.parsed.x.toFixed(1)}, ${ctx.parsed.y.toFixed(1)})`
                        }
                    }
                },
                scales: {
                    x: {
                        grid: { color: gc },
                        ticks: { color: tc, font: { size: 11 } },
                        title: { display: true, text: 'Packet size', color: tc, font: { size: 11 } }
                    },
                    y: {
                        grid: { color: gc },
                        ticks: { color: tc, font: { size: 11 } },
                        title: { display: true, text: 'Destination port', color: tc, font: { size: 11 } }
                    }
                }
            }
        });
    } else {
        // ✅ Just swap datasets — no destroy, no scroll jump
        scatterChart.data.datasets = datasets;
        scatterChart.update('none');
    }

    // Update custom legend
    updateScatterLegend(datasets);
}

function updateScatterLegend(datasets) {
    const el = document.getElementById('scatterLegend');
    if (!el) return;
    el.innerHTML = datasets.map(ds => `
        <span style="display:flex;align-items:center;gap:5px;font-size:12px;color:var(--color-text-secondary)">
            <span style="width:10px;height:10px;border-radius:${ds.pointStyle === 'triangle' ? '2px' : '50%'};background:${ds.pointBackgroundColor};border:1.5px solid ${ds.pointBorderColor};display:inline-block"></span>
            ${ds.label}
        </span>
    `).join('');
}