# RFID Lock

A simulated RFID door lock system designed for an Information Security and IoT capstone, demonstrating hardware token emulation, authentication evolution across multiple security modes (plain UID, UID + timestamp, and HMAC challenge-response), and vulnerability analysis against cloning, replay, and race-condition attacks.

## 1. Prerequisites & Setup (macOS)

1. **Install and start MySQL:**
   ```bash
   brew install mysql
   brew services start mysql
   ```
2. **Configure Environment:**
   Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
3. **Install Dependencies & Initialize:**
   ```bash
   npm install
   npm run db:init
   ```
   *(Note: `db:init` automatically creates the database, drops/recreates tables, seeds users, and generates `card/wallet.json`.)*

## 2. How to Run & Demo Script

Open **four** separate terminal windows in the project root:

| Terminal | Role | Command | Notes |
| :--- | :--- | :--- | :--- |
| **Terminal 1** | **Door Server & Dashboard** | `npm start` | Binds to port `3000`. Dashboard at http://127.0.0.1:3000 |
| **Terminal 2** | **Attacker Sniffing Proxy** | `npm run proxy` | Binds to port `3001` and forwards to `3000` |
| **Terminal 3** | **Legitimate RFID Card** | `npm run card -- ...` | Simulates user presenting their badge to reader (:3001) |
| **Terminal 4** | **Attacker Exploit Tool** | `npm run attack -- ...` | Executes automated penetration testing attacks |

---

### Step-by-Step Attack Walkthroughs

#### Attack A: Mode 1 (Plain UID) — Sniffing & Card Cloning
*Vulnerability:* The badge only sends a fixed, static identifier (`uid`) with zero authentication or encryption.

1. **Configure Mode:** On the Dashboard (http://127.0.0.1:3000), set **Active Mode** to **v1** (or select v1).
2. **Terminal 3 (Card):** Present legitimate admin card:
   ```bash
   npm run card -- --card admin --mode v1
   ```
   *Expected Output:*
   ```text
   [Card] Using admin card (UID: AA:BB:CC:DD)
   [Card] Target: http://127.0.0.1:3001  Mode: v1
   [Card] POST http://127.0.0.1:3001/api/v1/scan  body: { uid: 'AA:BB:CC:DD' }
   [Card] Reader responded HTTP 200: {"result":"granted","reason":"granted","uid":"AA:BB:CC:DD","mode":"v1"}
   ```
   *(Terminal 1 logs `[Door] UNLOCKED`, Terminal 2 logs `[Proxy] Captured POST /api/v1/scan`)*

3. **Terminal 4 (Attacker):** Clone the intercepted UID to a simulated card file:
   ```bash
   npm run attack -- clone
   ```
   *Expected Output:*
   ```text
   [Attacker] Cloned UID AA:BB:CC:DD to /Users/hardik/mac_only/Programs/rfid-lock/attacker/cloned-card.json
   ```

4. **Terminal 4 (Attacker):** Replay the cloned card against the door:
   ```bash
   npm run attack -- replay --mode v1
   ```
   *Expected Output:*
   ```text
   [Attacker] Replaying v1 scan: { uid: 'AA:BB:CC:DD' }
   [Attacker] Result: HTTP 200 {"result":"granted","reason":"granted","uid":"AA:BB:CC:DD","mode":"v1"}
   ```
   *(The door unlocks for the cloned card without needing the physical badge!)*

---

#### Attack B: Mode 2 (UID + Timestamp) — Timestamp Forgery
*Vulnerability:* The badge includes an ISO timestamp to prevent replays, but the message lacks a cryptographic signature/MAC. The attacker can forge fresh timestamps at will.

1. **Configure Mode:** On the Dashboard, set **Active Mode** to **v2**.
2. **Terminal 3 (Card):** Legitimate user taps card:
   ```bash
   npm run card -- --card admin --mode v2
   ```
   *Expected Output:*
   ```text
   [Card] Using admin card (UID: AA:BB:CC:DD)
   [Card] Target: http://127.0.0.1:3001  Mode: v2
   [Card] POST http://127.0.0.1:3001/api/v2/scan  body: { uid: 'AA:BB:CC:DD', ts: '2026-09-29T10:58:35.948Z' }
   [Card] Reader responded HTTP 200: {"result":"granted","reason":"granted","uid":"AA:BB:CC:DD","mode":"v2"}
   ```

3. **Terminal 4 (Attacker) — Test Simple Replay:** Wait 30 seconds for the original timestamp to expire, then run:
   ```bash
   npm run attack -- replay --mode v2
   ```
   *Expected Output:*
   ```text
   [Attacker] Replaying v2 scan: { uid: 'AA:BB:CC:DD', ts: '2026-09-29T10:58:35.948Z' }
   [Attacker] Result: HTTP 200 {"result":"denied","reason":"stale timestamp","uid":"AA:BB:CC:DD","mode":"v2"}
   ```
   *(Naïve replay is blocked by the 30-second TTL window).*

4. **Terminal 4 (Attacker) — Forge Fresh Timestamp:**
   ```bash
   npm run attack -- forge-ts
   ```
   *Expected Output:*
   ```text
   [Attacker] Forging fresh timestamp for v2 scan: { uid: 'AA:BB:CC:DD', ts: '2026-09-29T10:59:46.735Z' }
   [Attacker] Result: HTTP 200 {"result":"granted","reason":"granted","uid":"AA:BB:CC:DD","mode":"v2"}
   ```
   *(Access granted! Timestamp-only freshness without authentication fails completely).*

---

#### Attack C: Mode 3 (HMAC Challenge-Response) — Replay Resistance
*Security Mechanism:* Server sends an unpredictable single-use nonce; card responds with `HMAC-SHA256(secret, uid:nonce:readerId)`.

1. **Configure Mode:** On the Dashboard, set **Active Mode** to **v3**.
2. **Terminal 3 (Card):** Legitimate user taps card:
   ```bash
   npm run card -- --card admin --mode v3
   ```
   *Expected Output:*
   ```text
   [Card] Using admin card (UID: AA:BB:CC:DD)
   [Card] Target: http://127.0.0.1:3001  Mode: v3
   [Card] GET http://127.0.0.1:3001/api/v3/challenge?readerId=R1
   [Card] Received challenge: { challengeId: 'c3f191bb9f1a0e14db086cbde22bf731', nonce: '5a2f5a6b093685d03a11956555138139', expiresAt: '2026-09-29T11:05:00.000Z' }
   [Card] POST http://127.0.0.1:3001/api/v3/scan
   [Card] Reader responded HTTP 200: {"result":"granted","reason":"granted","uid":"AA:BB:CC:DD","mode":"v3"}
   ```

3. **Terminal 4 (Attacker) — Attempt Sequential Replay:**
   ```bash
   npm run attack -- replay --mode v3
   ```
   *Expected Output:*
   ```text
   [Attacker] Replaying v3 scan: { uid: 'AA:BB:CC:DD', challengeId: 'c3f191bb9f1a0e14db086cbde22bf731', response: '...' }
   [Attacker] Result: HTTP 200 {"result":"denied","reason":"nonce reused","uid":"AA:BB:CC:DD","mode":"v3"}
   ```
   *(Blocked! The nonce was marked as consumed when the card tapped).*

---

#### Attack D: Mode 3 — TOCTOU Race Condition Exploit (Vulnerable Mode)
*Vulnerability:* The server checks `SELECT used FROM nonces WHERE id = ?` and later updates `UPDATE nonces SET used = 1 WHERE id = ?`. A 20ms I/O latency window allows concurrent requests using the same nonce to pass validation before the database flags it as used.

1. **Configure Vulnerability State:** On the Dashboard, set **Race Condition Flaw** to **VULNERABLE** (default).
2. **Terminal 2 (Proxy):** Stop the proxy (`Ctrl+C`) and start it in **hold mode**:
   ```bash
   npm run proxy:hold
   ```
   *Expected Output:*
   ```text
   [Proxy] Listening on http://127.0.0.1:3001 -> forwarding to :3000
   [Proxy] HOLDING POST /api/v3/scan traffic for race demo.
   ```

3. **Terminal 3 (Card):** Present legitimate card:
   ```bash
   npm run card -- --card admin --mode v3
   ```
   *Expected Output:*
   ```text
   [Card] GET http://127.0.0.1:3001/api/v3/challenge?readerId=R1
   [Card] Received challenge: { ... }
   [Card] POST http://127.0.0.1:3001/api/v3/scan ...
   [Card] Reader responded HTTP 504: {"error":"reader timeout"}
   ```
   *(Terminal 2 logs `[Proxy] HOLDING v3 scan request. Will not forward to server.`. The attacker now has a valid, UNCONSUMED challenge-response token!)*

4. **Terminal 4 (Attacker):** Fire 10 parallel requests using the held token:
   ```bash
   npm run attack -- race --n 10
   ```
   *Expected Output:*
   ```text
   [Attacker] Firing 10 parallel v3 requests using intercepted nonce...
   [Attacker] Race complete. Requests granted: 2 out of 10
   ```
   *(Multiple requests are granted access concurrently for a single issued challenge nonce!)*

---

#### Attack E: Mode 3 — Atomic Mitigation Verification (Fixed Mode)
*Fix:* In fixed mode, the application checks challenge expiration in Node.js (`new Date(nonce.expires_at) >= new Date()`) and then atomically consumes the nonce via SQL:
```sql
UPDATE nonces SET used = 1 WHERE id = ? AND used = 0
```
InnoDB's row-level lock serializes concurrent updates: only the first request changes a row (`affectedRows === 1`); all concurrent requests see `affectedRows === 0` and are denied.

1. **Configure Vulnerability State:** On the Dashboard, toggle **Race Condition Flaw** to **FIXED**.
2. **Terminal 2 (Proxy):** Keep running `npm run proxy:hold` (or restart it if stopped).
3. **Terminal 3 (Card):** Present legitimate card again to capture a fresh held challenge:
   ```bash
   npm run card -- --card admin --mode v3
   ```
   *(Card will report HTTP 504 timeout again, and proxy logs the new scan).*

4. **Terminal 4 (Attacker):** Launch the 10 parallel race requests again:
   ```bash
   npm run attack -- race --n 10
   ```
   *Expected Output:*
   ```text
   [Attacker] Firing 10 parallel v3 requests using intercepted nonce...
   [Attacker] Race complete. Requests granted: 1 out of 10
   ```
   *(Only exactly 1 request succeeds; the remaining 9 are safely rejected as "nonce reused")*.

---

#### Attack F: Tamper-Evident Audit Log Detection
*Mechanism:* Each event log row in the `events` table includes a SHA-256 hash computed over `(prev_hash, ts, mode, uid, result, reason)`.

1. **Terminal 4 (Attacker):** Simulate database tampering (e.g., an insider modifying a denied scan to granted):
   ```bash
   npm run attack -- tamper-log
   ```
   *Expected Output:*
   ```text
   [Attacker] Connecting to database...
   [Attacker] Found denied event ID 4. Changing to 'granted'...
   [Attacker] Row 4 tampered! The hash chain is now broken.
   ```

2. **Dashboard Verification:**
   - In your browser dashboard (http://127.0.0.1:3000), click the **"Verify Hash Chain"** button.
   - *Expected Display:* Banner turns red: `Hash Chain Integrity: BROKEN at Event ID 4`.
   *(Or test via curl: `curl http://127.0.0.1:3000/api/events/verify`)*

## 3. Module Overview

* **`server/index.js`**: Express entry point. Demonstrates centralized IoT edge gateway architecture.
* **`server/config.js`**: In-memory runtime state. Demonstrates defense-in-depth through dynamic config separate from hardcoded secrets.
* **`server/door.js`**: Simulated actuator. Demonstrates fail-secure physical design (auto-relocks after 5s).
* **`server/audit.js`**: Hash-chained event logger. Demonstrates tamper-evident logging and non-repudiation.
* **`server/db.js`**: MySQL connection pool. Demonstrates parameterized queries preventing SQL injection.
* **`server/modes/v1.js`**: Plain UID auth. Demonstrates legacy proximity card flaws; enables clone/replay attacks.
* **`server/modes/v2.js`**: UID + Timestamp auth. Demonstrates the weakness of unauthenticated freshness; enables timestamp forgery.
* **`server/modes/v3.js`**: HMAC challenge-response. Demonstrates mutual authentication and replay prevention. Contains both the TOCTOU vulnerable path and the atomic-UPDATE fix.
* **`db/schema.sql`**: Relational tables. Demonstrates secure credential storage and single-use nonce modeling.
* **`db/init.js`**: Provisioning script. Demonstrates idempotent database setup and secure key generation.
* **`card/card.js`**: Smart card client. Demonstrates edge transponder emulation and client-side crypto (HMAC).
* **`attacker/proxy.js`**: MitM interceptor. Demonstrates eavesdropping and message-holding in wireless networks.
* **`attacker/attack.js`**: Exploit toolkit. Demonstrates practical penetration testing (replays, forgery, races).
* **`public/app.js`, `index.html`, `style.css`**: Dashboard UI. Demonstrates human-machine interfaces for security monitoring.
* **`test/matrix.js`**: Automated tester. Demonstrates security regression testing for IoT vulnerabilities.
