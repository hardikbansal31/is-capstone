// ─────────────────────────────────────────────────────────────────────────────
// server/door.js – Simulated door-lock actuator
//
// Maintains an in-memory LOCKED / UNLOCKED state.  On a successful auth the
// door unlocks for 5 seconds then auto-relocks — mimicking a fail-secure
// magnetic strike or solenoid lock on a real IoT door controller.
//
// Security concept: fail-secure design — the default state is LOCKED and the
// timeout ensures the door cannot be held open indefinitely by a single grant.
// ─────────────────────────────────────────────────────────────────────────────

import { Router } from 'express';

let state = 'LOCKED';
let since = new Date().toISOString();
let relockTimer = null;

/**
 * Unlock the door for 5 seconds, then auto-relock.
 * If called again while already unlocked, the timer resets.
 */
export function unlock() {
  state = 'UNLOCKED';
  since = new Date().toISOString();
  console.log(`[Door] UNLOCKED at ${since}`);

  // Clear any pending relock so repeated grants just extend the window.
  if (relockTimer) clearTimeout(relockTimer);

  relockTimer = setTimeout(() => {
    state = 'LOCKED';
    since = new Date().toISOString();
    relockTimer = null;
    console.log(`[Door] Auto-relocked at ${since}`);
  }, 5_000);

  // Don't let the timer prevent graceful process exit (important for tests).
  relockTimer.unref();
}

/** Return the current door state (for GET /api/door). */
export function getDoorState() {
  return { state, since };
}

/** Reset to LOCKED — used by tests between scenarios. */
export function resetDoor() {
  if (relockTimer) { clearTimeout(relockTimer); relockTimer = null; }
  state = 'LOCKED';
  since = new Date().toISOString();
}

// ── Express router ───────────────────────────────────────────────────────────
export const doorRouter = Router();
doorRouter.get('/', (_req, res) => res.json(getDoorState()));
