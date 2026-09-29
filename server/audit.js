// ─────────────────────────────────────────────────────────────────────────────
// server/audit.js – Hash-chained, tamper-evident audit log
//
// Every scan attempt (granted or denied) is appended to the `events` table.
// Each row's hash covers the previous row's hash plus the current row's
// fields, forming a cryptographic chain.  Tampering with any row breaks the
// chain from that point onward, which GET /api/events/verify detects.
//
// An in-process async queue serialises writes so the chain stays consistent
// even when many requests arrive in parallel (e.g. the race-condition demo).
//
// Security concepts: tamper-evident logging, non-repudiation, hash chains.
// ─────────────────────────────────────────────────────────────────────────────

import crypto  from 'node:crypto';
import { Router } from 'express';
import { pool }   from './db.js';

// The very first row in the chain uses this as its prev_hash (64 hex zeros).
const GENESIS_HASH = '0'.repeat(64);

// ── Async write queue ────────────────────────────────────────────────────────
// We chain every appendEvent call onto a single promise so that concurrent
// requests are serialised.  This guarantees that each row sees the correct
// prev_hash even under heavy parallel load.
let queue = Promise.resolve();

/**
 * Append one event to the audit log.
 * @param {{ mode: string, uid: string, result: string, reason: string }} data
 * @returns {Promise<object>} the inserted row data
 */
export function appendEvent({ mode, uid, result, reason }) {
  // Chain onto the queue so writes are strictly sequential.
  const job = queue.then(async () => {
    const ts = new Date().toISOString();

    // Fetch the hash of the most recent row (or use the genesis hash).
    const [lastRows] = await pool.query(
      'SELECT row_hash FROM events ORDER BY id DESC LIMIT 1'
    );
    const prevHash = lastRows.length ? lastRows[0].row_hash : GENESIS_HASH;

    // row_hash = SHA-256( prev_hash ‖ ts ‖ mode ‖ uid ‖ result ‖ reason )
    const rowHash = crypto
      .createHash('sha256')
      .update(prevHash + ts + mode + uid + result + reason)
      .digest('hex');

    await pool.query(
      `INSERT INTO events (ts, mode, uid, result, reason, prev_hash, row_hash)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [ts, mode, uid, result, reason, prevHash, rowHash]
    );

    return { ts, mode, uid, result, reason, prevHash, rowHash };
  });

  // Keep the chain alive even if one write fails (don't break subsequent writes).
  queue = job.catch((err) => console.error('[Audit] write failed:', err));
  return job;
}

// ── Express router ───────────────────────────────────────────────────────────
export const auditRouter = Router();

// GET /api/events – return the most recent 100 events (newest first).
auditRouter.get('/', async (_req, res) => {
  const [rows] = await pool.query(
    'SELECT * FROM events ORDER BY id DESC LIMIT 100'
  );
  res.json(rows);
});

// GET /api/events/verify – recompute the entire hash chain and report whether
// it is intact.  If any row has been tampered with, return the id where the
// chain breaks.
auditRouter.get('/verify', async (_req, res) => {
  const [rows] = await pool.query('SELECT * FROM events ORDER BY id ASC');

  let prevHash = GENESIS_HASH;
  for (const row of rows) {
    const expected = crypto
      .createHash('sha256')
      .update(prevHash + row.ts + row.mode + row.uid + row.result + row.reason)
      .digest('hex');

    if (expected !== row.row_hash) {
      return res.json({ valid: false, brokenAtId: Number(row.id) });
    }
    prevHash = row.row_hash;
  }

  res.json({ valid: true, rowCount: rows.length });
});
