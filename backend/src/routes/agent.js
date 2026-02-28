const express = require('express');
const router  = express.Router();
const {
    activateAgent,
    getIntelligence,
    getSubscriptionStatus,
    postAlert,
    getEndpoints,
    getAlerts,
} = require('../controllers/agentController');
const { protect } = require('../middleware/auth');

// ── Unauthenticated (called by C++ / Electron with session_token + HWID headers)
router.get('/intelligence',   getIntelligence);
router.get('/subscription',   getSubscriptionStatus);
router.post('/alert',         postAlert);
router.post('/activate',      activateAgent);   // session_token in body

// ── JWT-protected (called by React web dashboard)
router.get('/endpoints',      protect, getEndpoints);
router.get('/alerts',         protect, getAlerts);

module.exports = router;
