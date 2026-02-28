const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const bcrypt  = require('bcryptjs');
const config  = require('../config');

const dbPath = path.resolve(__dirname, '../../', config.db.path);

const db = new sqlite3.Database(dbPath, (err) => {
    if (err) { console.error('[DB] ❌ Connection error:', err.message); process.exit(1); }
    console.log('[DB] ✅ Connected to SQLite:', dbPath);
    db.run('PRAGMA journal_mode=WAL'); // better concurrency
    initSchema();
    runMigrations();
});

// ── Safe migrations: add columns that may be missing in older DB files ────────
function runMigrations() {
    const migrations = [
        `ALTER TABLE users ADD COLUMN session_token TEXT DEFAULT NULL`,
        `ALTER TABLE users ADD COLUMN session_hwid TEXT DEFAULT NULL`,
        `ALTER TABLE users ADD COLUMN subscription_ends DATETIME DEFAULT NULL`,
        `ALTER TABLE users ADD COLUMN beta_expires_at DATETIME DEFAULT (datetime('now', '+90 days'))`,
        `ALTER TABLE users ADD COLUMN last_login DATETIME`,
    ];
    migrations.forEach(sql => {
        db.run(sql, [], (err) => {
            // "duplicate column name" means it already exists — that's fine, ignore silently
            if (err && !err.message.includes('duplicate column name')) {
                console.warn('[DB] Migration warning:', err.message);
            }
        });
    });
    console.log('[DB] ✅ Migrations applied.');
}



function initSchema() {
    db.serialize(() => {

        // ── Users ──────────────────────────────────────────────────────────
        // subscription_status: 'beta' | 'active' | 'expired'
        // beta_expires_at: date when beta free access ends
        // session_token: the CURRENT valid session (one device at a time)
        // session_hwid: which device holds the active session
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id                  INTEGER  PRIMARY KEY AUTOINCREMENT,
                email               TEXT     UNIQUE NOT NULL,
                password            TEXT     NOT NULL,
                role                TEXT     DEFAULT 'user',
                subscription_status TEXT     DEFAULT 'beta',
                subscription_ends   DATETIME DEFAULT NULL,
                beta_expires_at     DATETIME DEFAULT (datetime('now', '+90 days')),
                session_token       TEXT     DEFAULT NULL,
                session_hwid        TEXT     DEFAULT NULL,
                created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
                last_login          DATETIME
            )
        `);

        // ── Registered Devices (endpoints) ────────────────────────────────
        db.run(`
            CREATE TABLE IF NOT EXISTS endpoints (
                id          INTEGER  PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER  NOT NULL,
                hwid        TEXT     UNIQUE NOT NULL,
                hostname    TEXT,
                os_version  TEXT,
                app_version TEXT,
                status      TEXT     DEFAULT 'online',
                last_seen   DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        `);

        // ── Threat Alerts logged from C++ engine ─────────────────────────
        db.run(`
            CREATE TABLE IF NOT EXISTS alerts (
                id         INTEGER  PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER  NOT NULL,
                hwid       TEXT     NOT NULL,
                type       TEXT,
                severity   TEXT,
                message    TEXT,
                remote_ip  TEXT,
                process    TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        `);

        // ── Seed default admin (only if env vars are set) ──────────────────
        db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
            if (!err && row.count === 0) {
                const adminEmail = process.env.ADMIN_EMAIL;
                const adminPass  = process.env.ADMIN_PASSWORD;
                if (!adminEmail || !adminPass) {
                    console.warn('[DB] ⚠ No admin seeded. Set ADMIN_EMAIL and ADMIN_PASSWORD in .env to create one.');
                    return;
                }
                if (adminPass.length < 8) {
                    console.warn('[DB] ⚠ ADMIN_PASSWORD must be at least 8 characters. Skipping seed.');
                    return;
                }
                const hash = bcrypt.hashSync(adminPass, 10);
                db.run(
                    `INSERT INTO users (email, password, role, subscription_status) VALUES (?, ?, ?, ?)`,
                    [adminEmail, hash, 'admin', 'active']
                );
                console.log(`[DB] 🔑 Admin seeded → ${adminEmail}`);
            }
        });
    });
}

module.exports = db;
