// ─────────────────────────────────────────────────────────────────────────────
// db/init.js – Database provisioning script
//
// Drops and recreates the database tables using schema.sql, then seeds exactly
// three cards: an active admin, an active staff, and a revoked card. Each is
// given a random 32-byte secret (used by Mode 3).
//
// The script also exports the generated UID/secret pairs into card/wallet.json
// so the simulated card client (card.js) has credentials to present.
//
// Security concept: idempotent provisioning of IoT device identities and secure
// key material generation.
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';

import fs       from 'node:fs/promises';
import path     from 'node:path';
import crypto   from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { pool } from '../server/db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function main() {
  console.log('[DB Init] Starting provisioning...');

  // 1. Read and execute the schema
  const schemaPath = path.join(__dirname, 'schema.sql');
  const schemaSql  = await fs.readFile(schemaPath, 'utf-8');

  try {
    await pool.query(schemaSql);
  } catch (e) {
    console.error(`Error executing schema:\n`, e);
    process.exit(1);
  }
  console.log('[DB Init] Schema created.');

  // 2. Clear out old data
  await pool.query('DELETE FROM cards');
  await pool.query('DELETE FROM nonces');
  await pool.query('DELETE FROM events');
  console.log('[DB Init] Old data cleared.');

  // 3. Seed cards
  const generateCard = (uid, holder, active) => ({
    uid,
    holder,
    active,
    secret_hex: crypto.randomBytes(32).toString('hex'), // 64 hex characters
  });

  const cards = [
    generateCard('AA:BB:CC:DD', 'Admin Alice', 1),
    generateCard('11:22:33:44', 'Staff Bob', 1),
    generateCard('EE:FF:00:11', 'Revoked Eve', 0),
  ];

  for (const c of cards) {
    await pool.query(
      'INSERT INTO cards (uid, holder, secret_hex, active) VALUES (?, ?, ?, ?)',
      [c.uid, c.holder, c.secret_hex, c.active]
    );
  }
  console.log('[DB Init] Seeded 3 cards.');

  // 4. Write wallet.json for the card client
  const wallet = {};
  for (const c of cards) {
    // The wallet maps simple names to the credentials for ease of use in the CLI.
    const key = c.holder.split(' ')[1].toLowerCase(); // alice, bob, eve
    // Also support calling them by role
    const roleKey = c.holder.split(' ')[0].toLowerCase(); // admin, staff, revoked
    const creds = { uid: c.uid, secret: c.secret_hex };
    wallet[key] = creds;
    wallet[roleKey] = creds;
  }

  const walletPath = path.join(__dirname, '..', 'card', 'wallet.json');
  await fs.writeFile(walletPath, JSON.stringify(wallet, null, 2), 'utf-8');
  console.log(`[DB Init] Wrote credentials to ${walletPath}`);

  console.log('[DB Init] Complete.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
