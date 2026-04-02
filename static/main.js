  // ── Clock ──
function tick() {
    document.getElementById('clock').textContent =
      new Date().toLocaleTimeString('en-GB', { hour12: false });
}
tick(); 
setInterval(tick, 1000);

// async function fetchLogs() {
//     try {

//         const response = await fetch("/api/logs");
//         const data = await response.json();

//         const tableBody = document.getElementById("log-table-body");
//         tableBody.innerHTML = "";
        
//         data.forEach(log => {

//             // Filter only web traffic
//             if (
//                 (log.protocol === "TCP" && (log.dst_port === 80 || log.dst_port === 443 || log.src_port === 80 || log.src_port === 443)) ||
//                 (log.protocol === "UDP" && (log.dst_port === 53 || log.src_port === 53))
//             ) {

//                 const row = `
//                     <tr>
//                         <td>${log.id}</td>
//                         <td>${log.timestamp}</td>
//                         <td>${log.src_ip}</td>
//                         <td>${log.dst_ip}</td>
//                         <td>${log.protocol}</td>
//                         <td>${log.src_port} → ${log.dst_port}</td>
//                         <td>${log.size}</td>
//                     </tr>
//                 `;

//                 tableBody.innerHTML += row;
//             }
//         });

//     } catch (error) {
//         console.error("Error fetching logs:", error);
//     }
// }

// // 🔁 Auto-refresh every 2 seconds
// setInterval(fetchLogs, 2000);

// // Load immediately
// fetchLogs();