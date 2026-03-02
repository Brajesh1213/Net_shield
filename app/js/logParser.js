/**
 * logParser.js — Backend Log Parser
 * Reads every raw line from the C++ engine stdout,
 * classifies it, and routes to the correct UI component.
 */

import { state } from './state.js';
import { stripAnsi, timeNow } from './utils.js';
import { appendLog } from './log.js';
import { addThreatRow, updateThreatStats } from './threats.js';
import { addAlert } from './alerts.js';

const API_BASE = 'http://localhost:5000/api';

/**
 * Parse a single raw log line from the C++ engine and update UI.
 * @param {string} rawLine
 */
export function processLogLine(rawLine) {
    const line  = stripAnsi(rawLine).trim();
    if (!line) return;

    const lower = line.toLowerCase();
    let   css   = 'info';

    // ── EDR Protective Ring hook success ──────────────────────────────────
    if (lower.includes('[edr]') && lower.includes('protective ring')) {
        css = 'success';
        addThreatRow({
            time:     timeNow(),
            category: 'EDR',
            severity: 'info',
            detail:   line.replace(/\[EDR\]\s*/i, '').trim().substring(0, 120),
            action:   'HOOKED',
        });
        // Not a real threat — do not increment counters

    // ── File threat ───────────────────────────────────────────────────────
    } else if (lower.includes('[file threat]')) {
        css = 'error';
        state.threatCount++;
        state.fileThreatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'FILE',
            severity: 'high',
            detail:   line.replace(/\[file threat\]\s*/i, '').trim().substring(0, 120),
            action:   'DETECTED',
        });
        addAlert(line, 'error', 'File Monitor');
        _postAlertToBackend({ type: 'file', severity: 'high', message: line });

    // ── Process threat ────────────────────────────────────────────────────
    } else if (lower.includes('[process threat]')) {
        css = 'error';
        state.threatCount++;
        state.procThreatCount++;
        state.timelineTick++;
        const isInject = lower.includes('memory injection');
        addThreatRow({
            time:     timeNow(),
            category: isInject ? 'INJECT' : 'PROCESS',
            severity: 'critical',
            detail:   line.replace(/\[process threat\]\s*/i, '').trim().substring(0, 120),
            action:   lower.includes('kill') || lower.includes('terminat') ? 'KILLED' : 'DETECTED',
        });
        addAlert(line, 'error', 'Process Monitor');
        _postAlertToBackend({ type: isInject ? 'memory_injection' : 'process', severity: 'critical', message: line });

    // ── Response engine kill/block ────────────────────────────────────────
    } else if (lower.includes('[responseengine] killed') || lower.includes('[blocked]')) {
        css = 'error';
        state.blockCount++;

    // ── Network threat ────────────────────────────────────────────────────
    } else if (lower.includes('high risk alert') || (lower.includes('[crit]') && lower.includes('network'))) {
        css = 'error';
        state.threatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'NETWORK',
            severity: 'critical',
            detail:   line.replace(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[CRIT\]/i, '').trim().substring(0, 120),
            action:   'ALERTED',
        });
        addAlert(line, 'warn', 'Network Monitor');

    // ── Warning ───────────────────────────────────────────────────────────
    } else if (lower.includes('[warn]') || lower.includes('warning')) {
        css = 'warn';

    // ── OK / success ──────────────────────────────────────────────────────
    } else if (lower.includes('[ok]') || lower.includes('initialized') || lower.includes('ready')) {
        css = 'success';
    }

    // Heartbeat → extract scan count
    const hb = line.match(/Scanned (\d+) connections/);
    if (hb) {
        state.scanCount = parseInt(hb[1], 10);
        document.getElementById('net-scanned').textContent = state.scanCount.toLocaleString();
    }

    appendLog(line + '\n', css);
    updateThreatStats();
}

// ── Private ────────────────────────────────────────────────────────────────

/**
 * Post a real threat event to the backend API (best-effort, supplemental).
 * The C++ engine also posts, this is an extra signal from the renderer.
 */
async function _postAlertToBackend({ type, severity, message, remoteIp = '', process = '' }) {
    try {
        await fetch(`${API_BASE}/agent/alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hwid: 'renderer', type, severity, message, remote_ip: remoteIp, process }),
        });
    } catch { /* best-effort */ }
}
