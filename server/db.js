// ─────────────────────────────────────────────────────────────────────────────
// server/db.js – MySQL connection pool
//
// Provides a shared mysql2/promise pool used by all server modules.
// Credentials come from process.env (loaded by dotenv in the entry point).
//
// Security concept: parameterised queries via the pool prevent SQL injection;
// connection pooling mirrors production IoT gateway persistence patterns.
// ─────────────────────────────────────────────────────────────────────────────

import mysql from 'mysql2/promise';

export const pool = mysql.createPool({
  host:              process.env.DB_HOST     || '127.0.0.1',
  user:              process.env.DB_USER     || 'root',
  password:          process.env.DB_PASSWORD || '',
  database:          process.env.DB_NAME     || 'rfid_lock',
  waitForConnections: true,
  connectionLimit:    20,          // enough for the parallel-race demo (10+)
  // Timezone alignment so DATETIME(3) columns compare correctly with NOW(3)
  timezone:          '+00:00',
  multipleStatements: true         // required for db/init.js schema execution
});
