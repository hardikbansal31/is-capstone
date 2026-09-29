// ─────────────────────────────────────────────────────────────────────────────
// public/app.js – Dashboard frontend logic
//
// Polls the server every second for door status and audit events.
// Handles configuration changes (mode/race flag) and hash chain verification.
//
// Security concept: Real-time telemetry monitoring for IoT deployments.
// ─────────────────────────────────────────────────────────────────────────────

// DOM Elements
const doorStateEl = document.getElementById('doorState');
const doorSinceEl = document.getElementById('doorSince');
const modeSelect  = document.getElementById('modeSelect');
const raceSelect  = document.getElementById('raceSelect');
const eventsBody  = document.querySelector('#eventsTable tbody');
const verifyBtn   = document.getElementById('verifyBtn');
const verifyBadge = document.getElementById('verifyBadge');

// ── State Polling ────────────────────────────────────────────────────────────

async function fetchDoorState() {
  try {
    const res = await fetch('/api/door');
    const data = await res.json();
    doorStateEl.textContent = data.state;
    doorStateEl.className = `state-${data.state}`;
    
    // Format timestamp nicely
    const d = new Date(data.since);
    doorSinceEl.textContent = d.toLocaleTimeString() + '.' + d.getMilliseconds();
  } catch (err) {
    console.error('Failed to fetch door state', err);
  }
}

async function fetchEvents() {
  try {
    const res = await fetch('/api/events');
    const rows = await res.json();
    
    eventsBody.innerHTML = '';
    
    for (const r of rows) {
      const tr = document.createElement('tr');
      if (r.result === 'denied') tr.classList.add('row-denied');
      if (r.result === 'granted') tr.classList.add('row-granted');
      
      const d = new Date(r.ts);
      const timeStr = d.toLocaleTimeString() + '.' + d.getMilliseconds().toString().padStart(3, '0');
      
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${timeStr}</td>
        <td>${r.mode}</td>
        <td>${r.uid}</td>
        <td class="result">${r.result}</td>
        <td>${r.reason}</td>
        <td class="hash" title="${r.row_hash}">${r.row_hash.substring(0, 16)}...</td>
      `;
      eventsBody.appendChild(tr);
    }
  } catch (err) {
    console.error('Failed to fetch events', err);
  }
}

// ── Configuration ────────────────────────────────────────────────────────────

async function fetchConfig() {
  try {
    const res = await fetch('/api/config');
    const data = await res.json();
    modeSelect.value = data.mode;
    raceSelect.value = data.raceVulnerable.toString();
  } catch (err) {
    console.error('Failed to fetch config', err);
  }
}

async function updateConfig() {
  const payload = {
    mode: modeSelect.value,
    raceVulnerable: raceSelect.value === 'true'
  };
  
  try {
    await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
  } catch (err) {
    console.error('Failed to update config', err);
  }
}

modeSelect.addEventListener('change', updateConfig);
raceSelect.addEventListener('change', updateConfig);

// ── Verification ─────────────────────────────────────────────────────────────

verifyBtn.addEventListener('click', async () => {
  verifyBadge.textContent = 'Verifying...';
  verifyBadge.className = 'badge';
  
  try {
    const res = await fetch('/api/events/verify');
    const data = await res.json();
    
    if (data.valid) {
      verifyBadge.textContent = `VALID (${data.rowCount} rows)`;
      verifyBadge.className = 'badge badge-valid';
    } else {
      verifyBadge.textContent = `BROKEN at ID ${data.brokenAtId}`;
      verifyBadge.className = 'badge badge-broken';
    }
  } catch (err) {
    console.error('Failed to verify', err);
    verifyBadge.textContent = 'Error';
  }
});

// ── Initialization ───────────────────────────────────────────────────────────

fetchConfig();
fetchDoorState();
fetchEvents();

// Poll every 1 second
setInterval(() => {
  fetchDoorState();
  fetchEvents();
}, 1000);
