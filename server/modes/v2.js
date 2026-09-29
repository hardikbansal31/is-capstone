// ─────────────────────────────────────────────────────────────────────────────
// server/modes/v2.js – Mode 2: UID + timestamp authentication
//
// The card sends its UID together with a timestamp.  The server checks that
// the UID is active and that |server_time − card_time| ≤ 30 seconds.
//
// VULNERABLE (intentional):
//   • The timestamp is NOT authenticated (not HMACed or signed).
//     An attacker who knows the UID can simply forge a fresh timestamp.
//   • Within the 30-second window, a byte-for-byte replay of a captured
//     message also succeeds.
//   • This models real systems that add "freshness" but forget to bind it
//     cryptographically to a shared secret.
//
// Attacks that succeed against v2:
//   – clone + replay UID   (within 30 s)
//   – forged timestamp
// ─────────────────────────────────────────────────────────────────────────────

import { Router }      from 'express';
import { pool }        from '../db.js';
import { getConfig }   from '../config.js';
import { appendEvent } from '../audit.js';
import { unlock }      from '../door.js';

export const v2Router = Router();

// POST /api/v2/scan   body: { uid, ts }
v2Router.post('/scan', async (req, res) => {
  // ── Gate: only respond when v2 is the active mode ──────────────────────
  if (getConfig().mode !== 'v2') {
    return res.status(409).json({ error: 'Mode v2 is not active' });
  }

  const { uid, ts } = req.body || {};
  if (!uid || !ts) return res.status(400).json({ error: 'Missing uid or ts' });

  // ── Freshness check: reject timestamps older than 30 seconds ───────────
  // VULNERABLE: the timestamp itself is not authenticated — anyone can
  // construct a valid message by pairing a known UID with Date.now().
  const drift = Math.abs(Date.now() - new Date(ts).getTime());
  if (drift > 30_000) {
    await appendEvent({ mode: 'v2', uid, result: 'denied', reason: 'stale timestamp' });
    return res.json({ result: 'denied', reason: 'stale timestamp', uid, mode: 'v2' });
  }

  // ── Look up the card ───────────────────────────────────────────────────
  const [cards] = await pool.query('SELECT * FROM cards WHERE uid = ?', [uid]);

  let result, reason;
  if (!cards.length) {
    result = 'denied'; reason = 'unknown uid';
  } else if (!cards[0].active) {
    result = 'denied'; reason = 'revoked';
  } else {
    result = 'granted'; reason = 'granted';
    unlock();
  }

  await appendEvent({ mode: 'v2', uid, result, reason });
  res.json({ result, reason, uid, mode: 'v2' });
});
