# RFID Lock

A simulated RFID door lock system designed for an Information Security and IoT capstone, demonstrating hardware token emulation, authentication evolution across multiple security modes (plain UID, hashed secrets, challenge-response), and vulnerability analysis against cloning, replay, and relay attacks.

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

1. **Server (The Lock & Dashboard):**
   ```bash
   npm start
   ```
   *Open http://127.0.0.1:3000 in your browser to view the monitoring dashboard.*

2. **Proxy (The Attacker's MitM Interceptor):**
   ```bash
   npm run proxy
   ```

3. **Card (The Legitimate User):**
   ```bash
   npm run card -- --card admin --mode v1
   ```

4. **Attacker (The Automated Exploits):**
   *(Run the commands below from this terminal as needed)*

### Step-by-Step Demo

**A. Mode 1 (Plain UID) - Cloning**
1. On Dashboard: Switch Active Mode to `v1`.
2. Card terminal: `npm run card -- --card admin --mode v1` (Door unlocks).
3. Attacker terminal:
   - `npm run attack -- clone` (Extracts UID).
   - `npm run attack -- replay --mode v1` (Successfully replays the exact payload, door unlocks).

**B. Mode 2 (UID + Timestamp) - Forgery**
1. On Dashboard: Switch Active Mode to `v2`.
2. Card terminal: `npm run card -- --card staff --mode v2` (Door unlocks).
3. Attacker terminal:
   - Wait 30 seconds.
   - `npm run attack -- replay --mode v2` (Fails: stale timestamp).
   - `npm run attack -- forge-ts` (Generates a new timestamp for the sniffed UID and succeeds, door unlocks).

**C. Mode 3 (HMAC Challenge-Response) - Replay Prevention**
1. On Dashboard: Switch Active Mode to `v3`.
2. Card terminal: `npm run card -- --card admin --mode v3` (Fetches challenge, computes HMAC, door unlocks).
3. Attacker terminal:
   - `npm run attack -- replay --mode v3` (Fails: nonce already used).

**D. Mode 3 - Race Condition Vulnerability**
1. On Dashboard: Ensure Race Vulnerability is set to `VULNERABLE`.
2. Stop the Proxy terminal (`Ctrl+C`) and restart it in hold mode:
   ```bash
   npm run proxy:hold
   ```
3. Card terminal: `npm run card -- --card admin --mode v3`
   *(Card hangs and fails with "reader timeout". The proxy captured the valid response but withheld it from the server.)*
4. Attacker terminal:
   ```bash
   npm run attack -- race --n 10
   ```
   *(Sends 10 identical requests in parallel. Because of the simulated 20ms I/O latency in the server, multiple requests hit the TOCTOU window before the nonce is marked used. The dashboard will show multiple "granted" events for the single challenge.)*

**E. Mode 3 - Race Condition Fix**
1. On Dashboard: Switch Race Vulnerability to `FIXED`.
2. Repeat the card tap (it will timeout again due to `proxy:hold`).
3. Run the attacker race command again:
   ```bash
   npm run attack -- race --n 10
   ```
   *(Only exactly 1 request is granted, the remaining 9 are denied as "nonce reused", demonstrating the efficacy of the atomic `UPDATE ... WHERE used=0` fix.)*

**F. Audit Log Tampering**
1. Attacker terminal:
   ```bash
   npm run attack -- tamper-log
   ```
   *(Simulates an attacker directly altering a 'denied' row in the database to 'granted').*
2. On Dashboard: Click "Verify Hash Chain". It will report `BROKEN at ID X`.

### Using Burp Suite (Optional)
Because the server uses plain HTTP and no CSRF tokens, you can easily proxy traffic through Burp Suite.
1. Point Burp at `127.0.0.1:3000`.
2. Intercept a legitimate `POST /api/v3/scan` request.
3. Send it to Repeater.
4. Duplicate the tab 10 times, add them to a group, and use the "Send group (parallel)" option to execute the race condition attack manually.

## 3. Results Matrix

| Attack | v1 | v2 | v3-vulnerable | v3-fixed |
| :--- | :--- | :--- | :--- | :--- |
| **clone + replay UID** | success | success (within 30s) | blocked | blocked |
| **forged timestamp** | n/a | success | blocked | blocked |
| **sequential replay of used v3 msg** | n/a | n/a | blocked | blocked |
| **parallel race, n=10** | n/a | n/a | >1 grants | exactly 1 grant |
| **log tamper then verify** | chain reports BROKEN | | | |

## 4. Module Overview

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

## 5. Limitations

* **Localhost Only:** The entire system runs on `127.0.0.1`. It does not demonstrate real-world network routing or physical radio constraints.
* **Simulated Hardware:** The card and door are software processes, not physical hardware.
* **Relay Attacks:** Holding a legitimate v3 message and sending it later is effectively a form of relay attack. The fixed version of v3 does *not* prevent this intrinsically; it is only mitigated by the 10-second challenge TTL.
* **Vulnerability Scope:** The race condition vulnerability shown results in multiple grants for a single-use nonce (a logical flaw), but doesn't necessarily open the door *longer* due to the absolute 5s relock timer.
* **No TLS:** Communication is plain HTTP to facilitate interception and learning. Real deployments must use TLS/HTTPS.
