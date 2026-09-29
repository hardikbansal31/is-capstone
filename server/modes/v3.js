// ─────────────────────────────────────────────────────────────────────────────
// server/modes/v3.js – Mode 3: HMAC challenge-response authentication
//
// Two-step protocol:
//   1. GET  /api/v3/challenge?readerId=R1  → { challengeId, nonce, expiresAt }
//   2. POST /api/v3/scan  { uid, challengeId, response }
//      where  response = HMAC-SHA256(secret, uid + ":" + nonce + ":" + readerId)
//
// The nonce is single-use and expires after 10 seconds.  The HMAC proves the
// card possesses the shared secret without transmitting it.
//
// TWO CODE PATHS (selected by the `raceVulnerable` runtime flag):
//
//   raceVulnerable = true   (v3-vulnerable)
//     SELECT → check used=0 → verify HMAC → 20 ms delay → UPDATE used=1.
//     The delay simulates real I/O latency.  Parallel requests all see used=0
//     before any of them flips it to 1 — classic TOCTOU race condition.
//     // VULNERABLE (intentional, for lab demo)
//
//   raceVulnerable = false  (v3-fixed)
//     Verify HMAC first, then atomically consume the nonce:
//       UPDATE nonces SET used=1 WHERE id=? AND used=0 AND expires_at > NOW(3)
//     Only the first request gets affectedRows=1; the rest are denied.
//     // FIX
//
// Attacks:
//   – Clone / replay / forged timestamp  →  BLOCKED (need the shared secret)
//   – Sequential replay of a used nonce  →  BLOCKED (used flag)
//   – Parallel race (n=10)               →  v3-vulnerable: >1 grant
//                                            v3-fixed:      exactly 1 grant
// ─────────────────────────────────────────────────────────────────────────────

import crypto        from 'node:crypto';
import { Router }    from 'express';
import { pool }      from '../db.js';
import { getConfig } from '../config.js';
import { appendEvent } from '../audit.js';
import { unlock }    from '../door.js';

export const v3Router = Router();

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/v3/challenge?readerId=R1
// Issue a fresh nonce for the reader.  The card must respond within 10 s.
// ─────────────────────────────────────────────────────────────────────────────
v3Router.get('/challenge', async (req, res) => {
  if (getConfig().mode !== 'v3') {
    return res.status(409).json({ error: 'Mode v3 is not active' });
  }

  const readerId    = req.query.readerId || 'R1';
  const challengeId = crypto.randomBytes(16).toString('hex');   // 32 hex chars
  const nonceHex    = crypto.randomBytes(16).toString('hex');   // 32 hex chars
  const expiresAt   = new Date(Date.now() + 10_000);           // 10-second TTL

  await pool.query(
    'INSERT INTO nonces (id, nonce_hex, reader_id, expires_at) VALUES (?, ?, ?, ?)',
    [challengeId, nonceHex, readerId, expiresAt]
  );

  res.json({
    challengeId,
    nonce: nonceHex,
    expiresAt: expiresAt.toISOString(),
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/v3/scan   body: { uid, challengeId, response }
// Verify the card's HMAC response against the stored nonce.
// ─────────────────────────────────────────────────────────────────────────────
v3Router.post('/scan', async (req, res) => {
  if (getConfig().mode !== 'v3') {
    return res.status(409).json({ error: 'Mode v3 is not active' });
  }

  const { uid, challengeId, response } = req.body || {};
  if (!uid || !challengeId || !response) {
    return res.status(400).json({ error: 'Missing uid, challengeId, or response' });
  }

  // ── Helpers ────────────────────────────────────────────────────────────
  const deny  = async (reason) => {
    await appendEvent({ mode: 'v3', uid, result: 'denied', reason });
    return res.json({ result: 'denied', reason, uid, mode: 'v3' });
  };
  const grant = async () => {
    unlock();
    await appendEvent({ mode: 'v3', uid, result: 'granted', reason: 'granted' });
    return res.json({ result: 'granted', reason: 'granted', uid, mode: 'v3' });
  };

  // Choose the code path based on the runtime flag.
  if (getConfig().raceVulnerable) {
    return handleVulnerable(uid, challengeId, response, deny, grant);
  } else {
    return handleFixed(uid, challengeId, response, deny, grant);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// VULNERABLE PATH  (intentional, for lab demo)
//
// The gap between "SELECT … check used=0" and "UPDATE used=1" is a TOCTOU
// race window.  The artificial 20 ms delay widens it so the demo is reliable.
// ─────────────────────────────────────────────────────────────────────────────
async function handleVulnerable(uid, challengeId, response, deny, grant) {
  // Step 1 – read the nonce row
  const [rows] = await pool.query('SELECT * FROM nonces WHERE id = ?', [challengeId]);
  if (!rows.length)                               return deny('unknown challenge');
  const nonce = rows[0];
  if (nonce.used)                                  return deny('nonce reused');
  if (new Date(nonce.expires_at) < new Date())     return deny('nonce expired');

  // Step 2 – look up the card
  const [cards] = await pool.query('SELECT * FROM cards WHERE uid = ?', [uid]);
  if (!cards.length)                               return deny('unknown uid');
  if (!cards[0].active)                            return deny('revoked');

  // Step 3 – verify HMAC  (constant-time comparison)
  const expected = crypto
    .createHmac('sha256', Buffer.from(cards[0].secret_hex, 'hex'))
    .update(`${uid}:${nonce.nonce_hex}:${nonce.reader_id}`)
    .digest('hex');

  const expectedBuf  = Buffer.from(expected,  'hex');
  const responseBuf  = Buffer.from(response,  'hex');
  if (expectedBuf.length !== responseBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, responseBuf)) {
    return deny('bad hmac');
  }

  // ┌─────────────────────────────────────────────────────────────────────┐
  // │  VULNERABLE (intentional, for lab demo)                            │
  // │  This 20 ms delay stands in for real I/O latency (e.g. writing    │
  // │  to an external audit bus).  During the delay, other parallel      │
  // │  requests can still SELECT the nonce and see used=0, because we   │
  // │  haven't updated it yet.  All of them will pass and be granted.   │
  // └─────────────────────────────────────────────────────────────────────┘
  await new Promise((r) => setTimeout(r, 20));          // VULNERABLE

  // Step 4 – mark nonce as used AFTER the delay  →  race window!
  await pool.query('UPDATE nonces SET used = 1 WHERE id = ?', [challengeId]);

  return grant();
}

// ─────────────────────────────────────────────────────────────────────────────
// FIXED PATH
//
// After HMAC verification succeeds, we atomically consume the nonce with a
// single UPDATE … WHERE used=0.  MySQL's row-level lock ensures that exactly
// one concurrent request gets affectedRows=1; the rest get 0 → denied.
// ─────────────────────────────────────────────────────────────────────────────
async function handleFixed(uid, challengeId, response, deny, grant) {
  // Step 1 – read the nonce data (we need nonce_hex and reader_id for HMAC)
  const [rows] = await pool.query('SELECT * FROM nonces WHERE id = ?', [challengeId]);
  if (!rows.length)                               return deny('unknown challenge');
  const nonce = rows[0];
  if (new Date(nonce.expires_at) < new Date())     return deny('nonce expired');

  // Step 2 – look up the card
  const [cards] = await pool.query('SELECT * FROM cards WHERE uid = ?', [uid]);
  if (!cards.length)                               return deny('unknown uid');
  if (!cards[0].active)                            return deny('revoked');

  // Step 3 – verify HMAC first (don't waste the atomic consume on bad auth)
  const expected = crypto
    .createHmac('sha256', Buffer.from(cards[0].secret_hex, 'hex'))
    .update(`${uid}:${nonce.nonce_hex}:${nonce.reader_id}`)
    .digest('hex');

  const expectedBuf  = Buffer.from(expected,  'hex');
  const responseBuf  = Buffer.from(response,  'hex');
  if (expectedBuf.length !== responseBuf.length ||
      !crypto.timingSafeEqual(expectedBuf, responseBuf)) {
    return deny('bad hmac');
  }

  // ┌─────────────────────────────────────────────────────────────────────┐
  // │  FIX: atomically consume the nonce.                                │
  // │  The WHERE clause checks used=0.                                   │
  // │  InnoDB's row lock serialises concurrent UPDATEs: only the first   │
  // │  request sees affectedRows=1, all others see 0 → denied.          │
  // └─────────────────────────────────────────────────────────────────────┘
  const [upd] = await pool.query(
    'UPDATE nonces SET used = 1 WHERE id = ? AND used = 0',
    [challengeId]
  );
  if (upd.affectedRows !== 1) return deny('nonce reused');          // FIX

  return grant();
}
