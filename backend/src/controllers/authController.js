const bcrypt  = require('bcryptjs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const db      = require('../db');
const AppError = require('../errors/AppError');
const config  = require('../config');

const dbGet = (sql, p) => new Promise((res, rej) => db.get(sql, p, (e, r) => e ? rej(e) : res(r)));
const dbRun = (sql, p) => new Promise((res, rej) => db.run(sql, p, function(e) { e ? rej(e) : res({ lastID: this.lastID }); }));

// ─── Register ──────────────────────────────────────────────────────────────
const register = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) throw new AppError('Email and password are required.', 400);
        if (password.length < 6)  throw new AppError('Password must be at least 6 characters.', 400);

        const existing = await dbGet(`SELECT id FROM users WHERE email = ?`, [email]);
        if (existing) throw new AppError('An account with this email already exists.', 409);

        const hash = await bcrypt.hash(password, 10);
        const { lastID } = await dbRun(
            `INSERT INTO users (email, password) VALUES (?, ?)`,
            [email, hash]
        );

        res.status(201).json({
            message: 'Account created. You have 90 days of free Beta access.',
            userId: lastID
        });
    } catch (err) { next(err); }
};

// ─── Login ─────────────────────────────────────────────────────────────────
// Single-device enforcement: generates a new session_token on every login,
// overwriting the previous one. The old device's next API call will fail.
const login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) throw new AppError('Email and password are required.', 400);

        const user = await dbGet(`SELECT * FROM users WHERE email = ?`, [email]);
        if (!user) throw new AppError('Invalid email or password.', 401);

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) throw new AppError('Invalid email or password.', 401);

        // ── Generate a new session token (kicks any previously logged-in device) ──
        const sessionToken = crypto.randomBytes(32).toString('hex');

        await dbRun(
            `UPDATE users SET session_token = ?, last_login = CURRENT_TIMESTAMP WHERE id = ?`,
            [sessionToken, user.id]
        );

        // ── Build JWT (for web dashboard use) ──
        const jwtToken = jwt.sign(
            { id: user.id, email: user.email, role: user.role },
            config.jwt.secret,
            { expiresIn: config.jwt.expiresIn }
        );

        // ── Determine subscription state ──
        const subInfo = resolveSubscription(user);

        res.json({
            message: 'Login successful.',
            token: jwtToken,             // used by React website
            session_token: sessionToken, // used by Electron / C++ agent
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                subscription: subInfo,
            },
        });
    } catch (err) { next(err); }
};

// ─── Get My Profile ────────────────────────────────────────────────────────
const getMe = async (req, res, next) => {
    try {
        const user = await dbGet(
            `SELECT id, email, role, subscription_status, subscription_ends, beta_expires_at, session_hwid, created_at, last_login FROM users WHERE id = ?`,
            [req.user.id]
        );
        if (!user) throw new AppError('User not found.', 404);
        res.json({ ...user, subscription: resolveSubscription(user) });
    } catch (err) { next(err); }
};

// ─── Logout ────────────────────────────────────────────────────────────────
const logout = async (req, res, next) => {
    try {
        await dbRun(`UPDATE users SET session_token = NULL, session_hwid = NULL WHERE id = ?`, [req.user.id]);
        res.json({ message: 'Logged out successfully.' });
    } catch (err) { next(err); }
};

// ─── Helper: resolve subscription state ───────────────────────────────────
// Returns an object the app can use directly without any extra logic.
function resolveSubscription(user) {
    const now = new Date();

    if (user.subscription_status === 'active') {
        // Paid subscription
        const ends = user.subscription_ends ? new Date(user.subscription_ends) : null;
        if (!ends || ends > now) {
            return { status: 'active', label: 'Active', message: null };
        }
        return { status: 'expired', label: 'Expired', message: 'Your subscription has expired. Please renew on our website.' };
    }

    if (user.subscription_status === 'beta') {
        const betaEnds = user.beta_expires_at ? new Date(user.beta_expires_at) : null;
        if (!betaEnds || betaEnds > now) {
            const daysLeft = betaEnds ? Math.ceil((betaEnds - now) / (1000 * 60 * 60 * 24)) : 90;
            return { status: 'beta', label: 'Beta', message: `Beta access: ${daysLeft} days remaining.` };
        }
        return {
            status: 'expired',
            label: 'Beta Expired',
            message: 'Your free Beta has ended. Subscribe at netsentinel.com to continue protection.',
            action_url: 'https://netsentinel.com/pricing',
        };
    }

    return { status: 'expired', label: 'Expired', message: 'No active subscription found.' };
}

module.exports = { register, login, getMe, logout, resolveSubscription };
