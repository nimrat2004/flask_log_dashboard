  // ── Clock ──
function tick() {
    document.getElementById('clock').textContent =
      new Date().toLocaleTimeString('en-GB', { hour12: false });
}
tick(); 
setInterval(tick, 1000);
console.log("Hello Jashan")
