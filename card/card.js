// ─────────────────────────────────────────────────────────────────────────────
// card/card.js – Simulated legitimate RFID smart card client
//
// Reads credentials from wallet.json, constructs the appropriate message for
// the chosen authentication mode, and sends it.  By default, it talks to the
// attacker's inline proxy (:3001) to simulate the card being scanned at a
// compromised reader.  The --direct flag bypasses the proxy to talk straight
// to the server (:3000).
//
// Security concept: edge device token emulation, client-side cryptographic
// proofs (HMAC for v3).
// ─────────────────────────────────────────────────────────────────────────────

import fs     from 'node:fs/promises';
import path   from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── CLI Argument Parsing ─────────────────────────────────────────────────────
const args = process.argv.slice(2);
let cardName = 'admin';
let mode     = 'v1';
let direct   = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--card')   cardName = args[++i];
  if (args[i] === '--mode')   mode     = args[++i];
  if (args[i] === '--direct') direct   = true;
}

const targetPort = direct ? 3000 : 3001;
const baseUrl    = `http://127.0.0.1:${targetPort}`;

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  // 1. Load wallet
  const walletPath = path.join(__dirname, 'wallet.json');
  let wallet;
  try {
    const data = await fs.readFile(walletPath, 'utf-8');
    wallet = JSON.parse(data);
  } catch (err) {
    console.error('Failed to read wallet.json. Did you run npm run db:init?');
    process.exit(1);
  }

  const creds = wallet[cardName.toLowerCase()];
  if (!creds) {
    console.error(`Card '${cardName}' not found in wallet.`);
    process.exit(1);
  }

  console.log(`[Card] Using ${cardName} card (UID: ${creds.uid})`);
  console.log(`[Card] Target: ${baseUrl}  Mode: ${mode}`);

  let payload;
  let endpoint = `/api/${mode}/scan`;

  // 2. Construct the message based on the mode
  if (mode === 'v1') {
    payload = { uid: creds.uid };
  } else if (mode === 'v2') {
    payload = { uid: creds.uid, ts: new Date().toISOString() };
  } else if (mode === 'v3') {
    // Mode 3 requires fetching a challenge first
    const chalUrl = `${baseUrl}/api/v3/challenge?readerId=R1`;
    console.log(`[Card] GET ${chalUrl}`);
    const chalRes = await fetch(chalUrl);
    
    if (!chalRes.ok) {
      console.error(`[Card] Challenge failed: ${chalRes.status}`);
      const text = await chalRes.text();
      console.error(`[Card] Response: ${text}`);
      process.exit(1);
    }
    
    const chal = await chalRes.json();
    console.log('[Card] Received challenge:', chal);

    // Compute response = HMAC-SHA256(secret, uid + ":" + nonce + ":" + readerId)
    const hmac = crypto.createHmac('sha256', Buffer.from(creds.secret, 'hex'));
    hmac.update(`${creds.uid}:${chal.nonce}:R1`);
    const response = hmac.digest('hex');

    payload = {
      uid: creds.uid,
      challengeId: chal.challengeId,
      response
    };
  } else {
    console.error(`Unknown mode: ${mode}`);
    process.exit(1);
  }

  // 3. Send the scan request
  console.log(`[Card] POST ${baseUrl}${endpoint}  body:`, payload);
  const res = await fetch(`${baseUrl}${endpoint}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  const resBody = await res.text();
  console.log(`[Card] Reader responded HTTP ${res.status}: ${resBody}`);
}

main().catch(console.error);
