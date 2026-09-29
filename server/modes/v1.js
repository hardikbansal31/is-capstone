// ─────────────────────────────────────────────────────────────────────────────
// server/modes/v1.js – Mode 1: Plain UID authentication
//
// The card sends only its static UID.  The server checks whether the UID
// exists and is active — nothing else.
//
// VULNERABLE (intentional):
//   • Anyone who observes (sniffs) the UID can clone the card and replay it
//     indefinitely.  There is no secret, no timestamp, and no challenge.
//   • This mirrors real-world legacy 125 kHz proximity cards (e.g. EM4100)
//     that transmit a fixed ID in the clear.
//
// Attacks that succeed against v1:
//   – clone + replay UID
// ─────────────────────────────────────────────────────────────────────────────

import { Router }      from 'express';
import { pool }        from '../db.js';
import { getConfig }   from '../config.js';
import { appendEvent } from '../audit.js';
import { unlock }      from '../door.js';

export const v1Router = Router();

// POST /api/v1/scan   body: { uid }
v1Router.post('/scan', async (req, res) => {
  // ── Gate: only respond when v1 is the active mode ──────────────────────
  if (getConfig().mode !== 'v1') {
    return res.status(409).json({ error: 'Mode v1 is not active' });
  }

  const { uid } = req.body || {};
  if (!uid) return res.status(400).json({ error: 'Missing uid' });

  // ── Look up the card ───────────────────────────────────────────────────
  const [cards] = await pool.query('SELECT * FROM cards WHERE uid = ?', [uid]);

  let result, reason;
  if (!cards.length) {
    result = 'denied'; reason = 'unknown uid';
  } else if (!cards[0].active) {
    result = 'denied'; reason = 'revoked';
  } else {
    // VULNERABLE: the UID alone is sufficient — no proof of possession.
    result = 'granted'; reason = 'granted';
    unlock();
  }

  // ── Audit ──────────────────────────────────────────────────────────────
  await appendEvent({ mode: 'v1', uid, result, reason });
  res.json({ result, reason, uid, mode: 'v1' });
});
