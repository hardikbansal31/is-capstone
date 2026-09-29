// ─────────────────────────────────────────────────────────────────────────────
// server/index.js – Express application entry point
//
// Wires together all API routes (config, door, audit, v1/v2/v3) and serves
// the static dashboard from public/.  Binds to 127.0.0.1 only — no remote
// access, plain HTTP, no CSRF tokens on scan endpoints (deliberate: the
// endpoints must be easy to hit from Burp Suite and attacker scripts).
//
// Security concept: central IoT edge gateway that mediates between cards,
// readers, actuators, and the monitoring dashboard.
// ─────────────────────────────────────────────────────────────────────────────

import 'dotenv/config';                        // load .env into process.env

import express          from 'express';
import path             from 'node:path';
import { fileURLToPath } from 'node:url';

import { configRouter } from './config.js';
import { doorRouter }   from './door.js';
import { auditRouter }  from './audit.js';
import { v1Router }     from './modes/v1.js';
import { v2Router }     from './modes/v2.js';
import { v3Router }     from './modes/v3.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── App factory (also used by tests) ─────────────────────────────────────────
export function createApp() {
  const app = express();

  // Parse JSON bodies for all POST endpoints.
  app.use(express.json());

  // ── API routes ─────────────────────────────────────────────────────────
  app.use('/api/config', configRouter);
  app.use('/api/door',   doorRouter);
  app.use('/api/events', auditRouter);
  app.use('/api/v1',     v1Router);
  app.use('/api/v2',     v2Router);
  app.use('/api/v3',     v3Router);

  // ── Static dashboard ──────────────────────────────────────────────────
  app.use(express.static(path.join(__dirname, '..', 'public')));

  return app;
}

// ── Server starter (returns the http.Server for programmatic control) ────────
export function startServer(port) {
  const app = createApp();
  const p   = Number(port || process.env.PORT || 3000);
  return new Promise((resolve) => {
    const server = app.listen(p, '127.0.0.1', () => {
      console.log(`[Server] RFID Lock listening on http://127.0.0.1:${p}`);
      resolve(server);
    });
  });
}

// ── Auto-start when run directly (`node server/index.js`) ────────────────────
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  startServer();
}
