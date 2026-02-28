const db      = require('../db');
const AppError = require('../errors/AppError');
const { resolveSubscription } = require('./authController');

const THREAT_INTEL = {
    version: '1.0.0',
    threat_intel: {
        high_risk_countries: ['KP', 'IR', 'SY', 'PK'],
        c2_ports: [4444, 1337, 8888, 31337, 9001],
        malware_hashes: [],
    },
    exclusions: {
        trusted_processes: ['code.exe', 'devenv.exe', 'chrome.exe', 'electron.exe'],
    },
};

const dbGet = (sql, p) => new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbRun = (sql, p) => new Promise((res, rej) => db.run(sql, p, function(e) { e ? rej(e) : res(this); }));
const dbAll = (sql, p) => new Promise((res, rej) => db.all(sql, p, (e, r) => e ? rej(e) : res(r)));

// ─── POST /api/agent/activate ─────────────────────────────────────────────
// Called by Electron app after login. Binds HWID to session.
// Also enforces single-device: if a different HWID tries to activate with
// the same session_token, we update the binding (kicking the old device).
const activateAgent = async (req, res, next) => {
    try {
        const { session_token, hwid, hostname, os_version, app_version } = req.body;
        if (!session_token || !hwid) throw new AppError('session_token and hwid are required.', 400);

        // Verify the session token
        const user = await dbGet(`SELECT * FROM users WHERE session_token = ?`, [session_token]);
        if (!user) throw new AppError('Invalid session. Please log in again.', 401);

        // Check subscription
        const sub = resolveSubscription(user);
        if (sub.status === 'expired') throw new AppError(sub.message, 403);

        // Bind this HWID to the session (kicks previous device)
        await dbRun(`UPDATE users SET session_hwid = ? WHERE id = ?`, [hwid, user.id]);

        // Upsert endpoint record
        const existing = await dbGet(`SELECT id FROM endpoints WHERE hwid = ?`, [hwid]);
        if (existing) {
            await dbRun(
                `UPDATE endpoints SET user_id=?, hostname=?, os_version=?, app_version=?, status='online', last_seen=CURRENT_TIMESTAMP WHERE hwid=?`,
                [user.id, hostname, os_version, app_version, hwid]
            );
        } else {
            await dbRun(
                `INSERT INTO endpoints (user_id, hwid, hostname, os_version, app_version) VALUES (?,?,?,?,?)`,
                [user.id, hwid, hostname, os_version, app_version]
            );
        }

        res.json({
            message: 'Agent activated.',
            subscription: sub,
            user: { id: user.id, email: user.email },
        });
    } catch (err) { next(err); }
};

// ─── GET /api/agent/intelligence ─────────────────────────────────────────
// Called by the C++ backend to fetch threat JSON.
// Requires: X-Session-Token and X-HWID headers.
// Enforces: the HWID must match the session's active device.
const getIntelligence = async (req, res, next) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        const hwid         = req.headers['x-hwid'];
        if (!sessionToken || !hwid) throw new AppError('Missing X-Session-Token or X-HWID header.', 400);

        const user = await dbGet(`SELECT * FROM users WHERE session_token = ?`, [sessionToken]);
        if (!user) throw new AppError('Invalid session. Please restart the app and log in.', 401);

        // ── Single-device enforcement ──────────────────────────────────
        // If a different device is using the same session, deny this one.
        if (user.session_hwid && user.session_hwid !== hwid) {
            throw new AppError(
                'This account is active on another device. Please log in again to switch devices.',
                409
            );
        }

        // ── Subscription check ────────────────────────────────────────
        const sub = resolveSubscription(user);
        if (sub.status === 'expired') throw new AppError(sub.message, 403);

        // Mark endpoint online
        await dbRun(
            `UPDATE endpoints SET status='online', last_seen=CURRENT_TIMESTAMP WHERE hwid=?`,
            [hwid]
        );

        res.json({ ...THREAT_INTEL, _meta: { subscription: sub } });
    } catch (err) { next(err); }
};

// ─── GET /api/agent/subscription ────────────────────────────────────────
// Electron app polls this every hour to check subscription state.
const getSubscriptionStatus = async (req, res, next) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        const hwid         = req.headers['x-hwid'];
        if (!sessionToken || !hwid) throw new AppError('Missing headers.', 400);

        const user = await dbGet(`SELECT * FROM users WHERE session_token = ?`, [sessionToken]);
        if (!user) throw new AppError('Invalid session.', 401);

        // single-device check
        if (user.session_hwid && user.session_hwid !== hwid) {
            return res.status(409).json({
                status: 'session_conflict',
                message: 'You have been logged out because the account was used on another device.',
            });
        }

        const sub = resolveSubscription(user);
        res.json({ subscription: sub, email: user.email });
    } catch (err) { next(err); }
};

// ─── POST /api/agent/alert ────────────────────────────────────────────────
const postAlert = async (req, res, next) => {
    try {
        const sessionToken = req.headers['x-session-token'];
        const { hwid, type, severity, message, remote_ip, process } = req.body;
        if (!hwid || !message) throw new AppError('hwid and message are required.', 400);

        const user = sessionToken
            ? await dbGet(`SELECT id FROM users WHERE session_token = ?`, [sessionToken])
            : await dbGet(`SELECT user_id as id FROM endpoints WHERE hwid = ?`, [hwid]);

        if (!user) throw new AppError('Unknown device.', 403);

        await dbRun(
            `INSERT INTO alerts (user_id, hwid, type, severity, message, remote_ip, process) VALUES (?,?,?,?,?,?,?)`,
            [user.id, hwid, type, severity, message, remote_ip, process]
        );
        res.status(201).json({ message: 'Alert logged.' });
    } catch (err) { next(err); }
};

// ─── GET /api/agent/endpoints  (requires JWT from web dashboard) ──────────
const getEndpoints = async (req, res, next) => {
    try {
        const rows = await dbAll(
            `SELECT id, hwid, hostname, os_version, app_version, status, last_seen FROM endpoints WHERE user_id = ?`,
            [req.user.id]
        );
        res.json(rows);
    } catch (err) { next(err); }
};

// ─── GET /api/agent/alerts  (requires JWT from web dashboard) ────────────
const getAlerts = async (req, res, next) => {
    try {
        const rows = await dbAll(
            `SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 100`,
            [req.user.id]
        );
        res.json(rows);
    } catch (err) { next(err); }
};

module.exports = { activateAgent, getIntelligence, getSubscriptionStatus, postAlert, getEndpoints, getAlerts };
