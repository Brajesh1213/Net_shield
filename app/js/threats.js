/**
 * threats.js — Threat Table + Stats component (Threats page)
 * Renders incoming threat events into the table and updates stat counters.
 */

import { state } from './state.js';
import { h } from './utils.js';

const threatsTbody = document.getElementById('threats-tbody');

// ── Badge maps ─────────────────────────────────────────────────────────────
const severityMap = {
    critical: '<span class="sev-dot sev-crit"></span>Critical',
    high:     '<span class="sev-dot sev-high"></span>High',
    medium:   '<span class="sev-dot sev-medium"></span>Medium',
    low:      '<span class="sev-dot sev-low"></span>Low',
    info:     '<span class="sev-dot sev-info"></span>Info',
};

const categoryBadgeMap = {
    FILE:    '<span class="badge badge-file">FILE</span>',
    PROCESS: '<span class="badge badge-process">PROCESS</span>',
    EDR:     '<span class="badge badge-edr">EDR HOOK</span>',
    INJECT:  '<span class="badge badge-inject">INJECT</span>',
    NETWORK: '<span class="badge badge-file">NETWORK</span>',
};

const actionBadgeMap = {
    KILLED:   '<span class="badge badge-killed">KILLED</span>',
    BLOCKED:  '<span class="badge badge-blocked">BLOCKED</span>',
    DETECTED: '<span class="badge badge-alert">DETECTED</span>',
    HOOKED:   '<span class="badge badge-hooked">HOOKED</span>',
    ALERTED:  '<span class="badge badge-alert">ALERTED</span>',
};

/**
 * Add a new row to the threat table (newest at top, max 100 rows).
 * @param {{ time: string, category: string, severity: string, detail: string, action: string }} evt
 */
export function addThreatRow({ time, category, severity, detail, action }) {
    const emptyRow = threatsTbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td style="color:#94a3b8;white-space:nowrap;font-size:11px;">${h(time)}</td>
        <td>${categoryBadgeMap[category] || `<span class="badge badge-low">${h(category)}</span>`}</td>
        <td>${severityMap[severity] || severity}</td>
        <td style="color:#475569;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${h(detail)}</td>
        <td>${actionBadgeMap[action] || `<span class="badge badge-low">${h(action)}</span>`}</td>
    `;
    threatsTbody.insertBefore(tr, threatsTbody.firstChild);
    while (threatsTbody.rows.length > 100) threatsTbody.deleteRow(threatsTbody.rows.length - 1);

    updateThreatStats();
}

/**
 * Sync all threat stat counters in the DOM from the global state.
 */
export function updateThreatStats() {
    document.getElementById('th-total').textContent    = state.threatCount;
    document.getElementById('th-blocked').textContent  = state.blockCount;
    document.getElementById('th-file').textContent     = state.fileThreatCount;
    document.getElementById('th-process').textContent  = state.procThreatCount;
    document.getElementById('prot-threats').textContent = state.threatCount;
    document.getElementById('prot-blocks').textContent  = state.blockCount;

    // Update nav badge
    const badge = document.getElementById('badge-threats');
    if (state.threatCount > 0) {
        badge.textContent = state.threatCount > 99 ? '99+' : state.threatCount;
        badge.style.display = 'block';
    }
}

/**
 * Clear all threat rows and reset counters.
 */
export function clearThreats() {
    state.threatCount = state.blockCount = state.fileThreatCount = state.procThreatCount = 0;
    threatsTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No threats detected this session — engine is watching…</td></tr>';
    document.getElementById('badge-threats').style.display = 'none';
    updateThreatStats();
}
