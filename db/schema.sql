-- ─────────────────────────────────────────────────────────────────────────────
-- RFID Lock – Database Schema
-- Defines tables for card credentials, challenge-response nonces, and a
-- hash-chained audit log.  Demonstrates secure credential storage,
-- single-use nonce management, and tamper-evident logging for IoT devices.
-- ─────────────────────────────────────────────────────────────────────────────

-- Registered RFID cards.  `secret_hex` is a 32-byte (256-bit) shared secret
-- stored as 64 hex characters — used by Mode 3 (HMAC challenge-response).
-- The `active` flag allows revocation without deleting history.
CREATE TABLE IF NOT EXISTS cards (
  uid        VARCHAR(16)  NOT NULL PRIMARY KEY,
  holder     VARCHAR(64)  NOT NULL,
  secret_hex CHAR(64)     NOT NULL,
  active     TINYINT      NOT NULL DEFAULT 1
);

-- One-time challenge nonces for Mode 3.  Each row represents a pending
-- challenge issued by the reader.  `used` is flipped to 1 when the card
-- responds; the atomic UPDATE on this column is the fix for the race-
-- condition vulnerability demonstrated in the lab.
CREATE TABLE IF NOT EXISTS nonces (
  id          CHAR(32)     NOT NULL PRIMARY KEY,
  nonce_hex   CHAR(32)     NOT NULL,
  reader_id   VARCHAR(16)  NOT NULL,
  expires_at  DATETIME(3)  NOT NULL,
  used        TINYINT      NOT NULL DEFAULT 0
);

-- Append-only, hash-chained audit log.  Each row's `row_hash` is
-- SHA-256(prev_hash ‖ ts ‖ mode ‖ uid ‖ result ‖ reason), chaining every
-- event to its predecessor.  Tampering with any row breaks the chain from
-- that point onward — detectable by GET /api/events/verify.
CREATE TABLE IF NOT EXISTS events (
  id        BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
  ts        VARCHAR(32)  NOT NULL,
  mode      VARCHAR(16)  NOT NULL,
  uid       VARCHAR(16)  NOT NULL,
  result    VARCHAR(8)   NOT NULL,
  reason    VARCHAR(64)  NOT NULL,
  prev_hash CHAR(64)     NOT NULL,
  row_hash  CHAR(64)     NOT NULL
);
