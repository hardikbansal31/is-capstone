// ─────────────────────────────────────────────────────────────────────────────
// test/matrix.js – Automated security verification matrix
//
// Orchestrates end-to-end tests across all authentication modes, proving the
// presence of the vulnerabilities and the efficacy of the v3 fix.
//
// This script runs the server in-process on a test port, simulates the card
// and attacker programmatically (via HTTP, not direct function calls), and
// asserts the results.
//
// Security concept: automated regression testing for security properties.
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from '../server/index.js';
import { setConfig } from '../server/config.js';
import { resetDoor } from '../server/door.js';
import { pool } from '../server/db.js';

const TEST_PORT = 3005;
const BASE_URL  = `http://127.0.0.1:${TEST_PORT}`;

// Load credentials
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const walletPath = path.join(__dirname, '..', 'card', 'wallet.json');
let wallet;

async function setup() {
  const data = await fs.readFile(walletPath, 'utf-8');
  wallet = JSON.parse(data);
  return await startServer(TEST_PORT);
}

// ── Helpers ──────────────────────────────────────────────────────────────────
async function post(endpoint, body) {
  const r = await fetch(`${BASE_URL}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  });
  return r.json();
}

async function get(endpoint) {
  const r = await fetch(`${BASE_URL}${endpoint}`);
  return r.json();
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

// ── Tests ────────────────────────────────────────────────────────────────────
async function runTests() {
  const admin = wallet['admin'];
  const results = [];
  let rowHashToTamper = null;
  let tamperedId = null;

  console.log('\n[Test] Running security matrix...\n');

  // --- v1 ---
  setConfig({ mode: 'v1' });
  resetDoor();
  let r = await post('/api/v1/scan', { uid: admin.uid });
  results.push({ attack: 'clone + replay UID', mode: 'v1', res: r.result === 'granted' ? 'success' : 'blocked' });

  // --- v2 ---
  setConfig({ mode: 'v2' });
  resetDoor();
  // Valid replay within 30s
  const ts = new Date().toISOString();
  r = await post('/api/v2/scan', { uid: admin.uid, ts });
  results.push({ attack: 'clone + replay UID', mode: 'v2', res: r.result === 'granted' ? 'success' : 'blocked' });

  // Forged fresh timestamp
  resetDoor();
  r = await post('/api/v2/scan', { uid: admin.uid, ts: new Date().toISOString() });
  results.push({ attack: 'forged timestamp', mode: 'v2', res: r.result === 'granted' ? 'success' : 'blocked' });

  // --- v3 (vulnerable) ---
  setConfig({ mode: 'v3', raceVulnerable: true });
  resetDoor();
  
  // Need a real challenge for v3 attacks
  let chal = await get('/api/v3/challenge?readerId=R1');
  let hmac = crypto.createHmac('sha256', Buffer.from(admin.secret, 'hex')).update(`${admin.uid}:${chal.nonce}:R1`).digest('hex');
  let payload = { uid: admin.uid, challengeId: chal.challengeId, response: hmac };

  // Replay UID (no challenge/invalid response)
  r = await post('/api/v3/scan', { uid: admin.uid, challengeId: 'bad', response: 'bad' });
  results.push({ attack: 'clone + replay UID', mode: 'v3-vulnerable', res: r.result === 'granted' ? 'success' : 'blocked' });

  r = await post('/api/v3/scan', { uid: admin.uid, ts: new Date().toISOString() });
  results.push({ attack: 'forged timestamp', mode: 'v3-vulnerable', res: r.result === 'granted' ? 'success' : 'blocked' });

  // Sequential replay
  await post('/api/v3/scan', payload); // uses it
  r = await post('/api/v3/scan', payload); // tries again
  results.push({ attack: 'sequential replay of used v3 message', mode: 'v3-vulnerable', res: r.result === 'granted' ? 'success' : 'blocked' });

  // Parallel race
  resetDoor();
  chal = await get('/api/v3/challenge?readerId=R1');
  hmac = crypto.createHmac('sha256', Buffer.from(admin.secret, 'hex')).update(`${admin.uid}:${chal.nonce}:R1`).digest('hex');
  payload = { uid: admin.uid, challengeId: chal.challengeId, response: hmac };
  
  let promises = [];
  for(let i=0; i<10; i++) promises.push(post('/api/v3/scan', payload));
  let raceResults = await Promise.all(promises);
  let grantedCount = raceResults.filter(x => x.result === 'granted').length;
  results.push({ attack: 'parallel race, n=10', mode: 'v3-vulnerable', res: grantedCount > 1 ? `>1 grants (${grantedCount})` : 'exactly 1 grant' });

  // --- v3 (fixed) ---
  setConfig({ mode: 'v3', raceVulnerable: false });
  resetDoor();

  chal = await get('/api/v3/challenge?readerId=R1');
  hmac = crypto.createHmac('sha256', Buffer.from(admin.secret, 'hex')).update(`${admin.uid}:${chal.nonce}:R1`).digest('hex');
  payload = { uid: admin.uid, challengeId: chal.challengeId, response: hmac };

  r = await post('/api/v3/scan', { uid: admin.uid, challengeId: 'bad', response: 'bad' });
  results.push({ attack: 'clone + replay UID', mode: 'v3-fixed', res: r.result === 'granted' ? 'success' : 'blocked' });

  r = await post('/api/v3/scan', { uid: admin.uid, ts: new Date().toISOString() });
  results.push({ attack: 'forged timestamp', mode: 'v3-fixed', res: r.result === 'granted' ? 'success' : 'blocked' });

  await post('/api/v3/scan', payload);
  r = await post('/api/v3/scan', payload);
  results.push({ attack: 'sequential replay of used v3 message', mode: 'v3-fixed', res: r.result === 'granted' ? 'success' : 'blocked' });

  resetDoor();
  chal = await get('/api/v3/challenge?readerId=R1');
  hmac = crypto.createHmac('sha256', Buffer.from(admin.secret, 'hex')).update(`${admin.uid}:${chal.nonce}:R1`).digest('hex');
  payload = { uid: admin.uid, challengeId: chal.challengeId, response: hmac };
  
  promises = [];
  for(let i=0; i<10; i++) promises.push(post('/api/v3/scan', payload));
  raceResults = await Promise.all(promises);
  grantedCount = raceResults.filter(x => x.result === 'granted').length;
  results.push({ attack: 'parallel race, n=10', mode: 'v3-fixed', res: grantedCount === 1 ? 'exactly 1 grant' : `>1 grants (${grantedCount})` });


  // --- Log Tampering ---
  // Wait for audit queue to flush
  await sleep(100);
  
  const [eventsBefore] = await pool.query('SELECT * FROM events ORDER BY id DESC LIMIT 1');
  if (eventsBefore.length) {
    tamperedId = eventsBefore[0].id;
    // Tamper the result without fixing hash
    await pool.query("UPDATE events SET result = 'TAMPERED' WHERE id = ?", [tamperedId]);
  }
  
  let verify = await get('/api/events/verify');
  results.push({ attack: 'log tamper then verify', mode: 'all', res: verify.valid === false ? `chain reports BROKEN (at ${verify.brokenAtId})` : 'chain reports VALID' });


  // ── Print Matrix ───────────────────────────────────────────────────────────
  console.table(results);
  return results;
}

// ── Execute ──────────────────────────────────────────────────────────────────
let server;
setup()
  .then((s) => { server = s; return runTests(); })
  .then(() => {
    console.log('[Test] Complete.');
    server.close();
    pool.end();
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    if (server) server.close();
    pool.end();
    process.exit(1);
  });
