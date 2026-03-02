/**
 * buttons.js — Misc Button Wiring
 * Wires all action buttons that don't belong to a single component:
 *   - Log controls (clear, export)
 *   - Engine restart
 *   - Threats/Alerts clear
 *   - Alert filter chips
 *   - Network refresh
 *   - Logout
 */

import { clearLog, exportLog } from './log.js';
import { clearThreats, updateThreatStats } from './threats.js';
import { clearAlerts, applyAlertFilter } from './alerts.js';
import { loadNetworkConnections } from './network.js';
import { setEngineRunning } from './engine.js';
import { appendLog } from './log.js';
import { state } from './state.js';

const threatsTbody = document.getElementById('threats-tbody');

/**
 * Wire all miscellaneous action buttons.
 */
export function initMiscButtons() {

    // ── Log controls ──────────────────────────────────────────────────────
    document.getElementById('clear-log-btn')?.addEventListener('click', clearLog);
    document.getElementById('export-log-btn')?.addEventListener('click', exportLog);

    // ── Engine restart (available from both Protection + More pages) ──────
    const doRestart = async () => {
        appendLog('--- Restarting engine… ---\n', 'warn');
        await window.electronAPI.stopBackend();
        setTimeout(async () => {
            const res = await window.electronAPI.startBackend();
            if (res.success) {
                setEngineRunning(true);
                appendLog('--- Engine restarted ---\n', 'success');
            }
        }, 2000);
    };
    document.getElementById('restart-engine-btn')?.addEventListener('click', doRestart);
    document.getElementById('more-restart-btn')?.addEventListener('click', doRestart);

    // ── More page: Export + Clear all ────────────────────────────────────
    document.getElementById('more-export-btn')?.addEventListener('click', exportLog);

    const clearAll = () => {
        clearLog();
        state.threatCount = state.blockCount =
        state.fileThreatCount = state.procThreatCount = state.scanCount = 0;
        threatsTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No threats detected this session — engine is watching…</td></tr>';
        updateThreatStats();
    };
    document.getElementById('more-clear-btn')?.addEventListener('click', clearAll);

    // ── Threats page: Clear All ───────────────────────────────────────────
    document.getElementById('clear-threats-btn')?.addEventListener('click', clearThreats);

    // ── Alerts page: Clear All ────────────────────────────────────────────
    document.getElementById('clear-alerts-btn')?.addEventListener('click', clearAlerts);

    // ── Alert filter chips ────────────────────────────────────────────────
    document.querySelectorAll('.chip').forEach(chip => {
        chip.addEventListener('click', () => applyAlertFilter(chip.dataset.filter));
    });

    // ── Network page: Refresh ─────────────────────────────────────────────
    document.getElementById('refresh-net-btn')?.addEventListener('click', loadNetworkConnections);

    // ── Profile page: Logout ──────────────────────────────────────────────
    document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await window.electronAPI.logoutUser();
        await window.electronAPI.stopBackend();
        location.reload();
    });
}
