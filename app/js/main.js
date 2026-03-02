/**
 * main.js — Application Entry Point (ES Module)
 *
 * Boots all components in order after DOMContentLoaded.
 * Wires IPC event listeners (engine log, stopped, threats, subscription).
 *
 * Pages:
 *   protection  — Engine ON/OFF + live log + stats
 *   threats     — Threat event table + timeline chart
 *   network     — Live netstat connections + GeoIP
 *   alerts      — Alert feed with filter chips
 *   more        — Profile + settings + troubleshoot
 *
 * IPC bridge:  window.electronAPI  (injected by preload.js)
 * Backend:     http://localhost:5000/api
 * C++ engine:  spawned by main.js (Electron), logs via onBackendLog
 */

import { initRouter }      from './router.js';
import { initEngineToggle, setEngineRunning } from './engine.js';
import { initAdminStatus } from './adminStatus.js';
import { initChart }       from './chart.js';
import { initLogin }       from './login.js';
import { initMiscButtons } from './buttons.js';
import { handleSubscription, loadProfile } from './profile.js';
import { processLogLine }  from './logParser.js';
import { addThreatRow }    from './threats.js';
import { updateThreatStats } from './threats.js';
import { addAlert }        from './alerts.js';
import { appendLog }       from './log.js';
import { timeNow }         from './utils.js';
import { state }           from './state.js';

document.addEventListener('DOMContentLoaded', async () => {

    // ── Boot all components ───────────────────────────────────────────────
    initRouter();
    initEngineToggle();
    initAdminStatus();
    initChart();
    const { hideOverlay } = initLogin();
    initMiscButtons();

    // ── Auto-login (restore saved session) ───────────────────────────────
    const sub = await window.electronAPI.getSubscription();

    if (sub) {
        // Always persist the subscription status to state first
        // so engine.js can gate engine start properly
        handleSubscription(sub);

        if (sub.status === 'expired') {
            // Keep login overlay visible — don't auto-restore expired sessions
            appendLog('[AUTH] ⚠ Saved session found but subscription is expired.\n', 'warn');
        } else {
            // Valid session — restore and auto-start engine
            hideOverlay();
            appendLog('[AUTH] ✅ Session restored.\n', 'success');

            const eng = await window.electronAPI.startBackend();
            if (eng.success) {
                setEngineRunning(true);
                appendLog('--- Asthak Engine Initialized ---\n', 'success');
            }
            loadProfile();
        }
    }

    // ── Sync current engine running state ────────────────────────────────
    const running = await window.electronAPI.checkStatus();
    if (running) setEngineRunning(true);

    // ── IPC: stream C++ engine log lines ─────────────────────────────────
    window.electronAPI.onBackendLog((data) => {
        data.split('\n').forEach(rawLine => processLogLine(rawLine));
    });

    // ── IPC: engine process exited ───────────────────────────────────────
    window.electronAPI.onBackendStopped(() => {
        setEngineRunning(false);
        appendLog('--- Engine stopped ---\n', 'warn');
    });

    // ── IPC: threat events from main-process high-risk parser ────────────
    window.electronAPI.onThreatDetected((threat) => {
        state.threatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'NETWORK',
            severity: 'critical',
            detail:   threat.message.substring(0, 120),
            action:   threat.isBlock ? 'BLOCKED' : 'ALERTED',
        });
        addAlert(threat.message, 'error', 'Network Monitor');
        updateThreatStats();
    });

    // ── IPC: subscription status alerts ──────────────────────────────────
    window.electronAPI.onSubscriptionAlert((data) => handleSubscription(data));
});
