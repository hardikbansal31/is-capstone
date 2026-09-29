// ─────────────────────────────────────────────────────────────────────────────
// server/config.js – Runtime configuration store
//
// Holds the *active* authentication mode (v1 | v2 | v3) and the race-
// condition flag in memory.  Switching is done at runtime via the API so a
// demo can walk through all modes without restarting the server.
//
// Security concept: defence-in-depth through configuration management —
// secrets live in .env, operational knobs live here, nothing is hard-coded.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

// ── In-memory runtime state ──────────────────────────────────────────────────
let mode           = 'v1';   // 'v1' | 'v2' | 'v3'
let raceVulnerable = true;   // true  → use the racy v3 code path (lab demo)
                              // false → use the fixed atomic-UPDATE path

/** Return a snapshot of the current runtime config. */
export function getConfig() {
  return { mode, raceVulnerable };
}

/** Merge partial updates into the runtime config. */
export function setConfig(updates = {}) {
  if (updates.mode !== undefined)           mode           = updates.mode;
  if (updates.raceVulnerable !== undefined) raceVulnerable = updates.raceVulnerable;
}

// ── Express router: GET / POST  /api/config ──────────────────────────────────
export const configRouter = Router();

configRouter.get('/', (_req, res) => {
  res.json(getConfig());
});

configRouter.post('/', (req, res) => {
  const { mode: m, raceVulnerable: r } = req.body;
  if (m !== undefined && !['v1', 'v2', 'v3'].includes(m)) {
    return res.status(400).json({ error: `Invalid mode "${m}". Use v1, v2, or v3.` });
  }
  setConfig({ mode: m, raceVulnerable: r });
  console.log(`[Config] mode=${getConfig().mode}  raceVulnerable=${getConfig().raceVulnerable}`);
  res.json(getConfig());
});
