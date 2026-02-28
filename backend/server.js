const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const config = require('./src/config');

// Initialize DB (runs schema creation on import)
require('./src/db');

// Routers
const authRoutes  = require('./src/routes/auth');
const agentRoutes = require('./src/routes/agent');

// Error handler (must be last)
const errorHandler = require('./src/errors/errorHandler');

const app = express();

// ─── Global Middleware ─────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

// ─── Rate Limiting ────────────────────────────────────────────
// Strict limiter for auth endpoints (prevent brute-force)
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5,                   // 5 attempts per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many login attempts. Please try again in 15 minutes.' },
});

// General API limiter
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,                 // 100 requests per window
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 'error', message: 'Too many requests. Please slow down.' },
});
app.use('/api/', apiLimiter);

// ─── Request Logger (dev only) ────────────────────────────────
if (config.server.nodeEnv === 'development') {
    app.use((req, _res, next) => {
        console.log(`[${req.method}] ${req.url}`);
        next();
    });
}

// ─── Routes ───────────────────────────────────────────────────
app.get('/api/health', (_req, res) => res.json({ status: 'ok', version: '1.0.0' }));
app.use('/api/auth',  authLimiter, authRoutes);
app.use('/api/agent', agentRoutes);

// 404 catch-all
app.use((_req, res) => {
    res.status(404).json({ status: 'error', message: 'Route not found.' });
});

// ─── Global Error Handler ─────────────────────────────────────
app.use(errorHandler);

// ─── Start Server ─────────────────────────────────────────────
const PORT = config.server.port;
app.listen(PORT, () => {
    console.log(`🚀 NetSentinel Backend running on http://localhost:${PORT}`);
    console.log(`   Environment: ${config.server.nodeEnv}`);
});
