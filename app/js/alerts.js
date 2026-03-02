/**
 * alerts.js — Alerts Feed component (Alerts page)
 * Adds, filters, and clears security alert cards.
 */

import { state } from './state.js';
import { h, timeNow } from './utils.js';

const alertsList = document.getElementById('alerts-list');

// ── SVG icons for each alert type ─────────────────────────────────────────
const iconSvg = {
    error:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
    warn:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>',
    success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
};

const EMPTY_STATE_HTML = `
    <div class="empty-state">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#cbd5e1" stroke-width="1.5">
            <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
            <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
        </svg>
        <p>No alerts yet — system is clean ✓</p>
    </div>`;

/**
 * Add a new alert card (newest at top, max 100).
 * @param {string} msg
 * @param {'error'|'warn'|'success'} type
 * @param {string} source - optional source label
 */
export function addAlert(msg, type = 'warn', source = '') {
    // Remove empty-state placeholder
    const empty = alertsList.querySelector('.empty-state');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = `alert-item ${type}`;
    item.dataset.filter = type;
    item.innerHTML = `
        <div class="alert-icon ${type}">${iconSvg[type] || iconSvg.warn}</div>
        <div class="alert-body">
            <div class="alert-msg">${h(msg.substring(0, 250))}</div>
            <div class="alert-meta">${timeNow()}${source ? ' · ' + h(source) : ''}</div>
        </div>
    `;
    alertsList.insertBefore(item, alertsList.firstChild);
    state.allAlerts.unshift({ el: item, type });

    // Apply current visibility filter
    applyAlertFilter(state.currentFilter);

    // Keep max 100 entries
    while (state.allAlerts.length > 100) {
        const old = state.allAlerts.pop();
        if (old.el.parentNode) old.el.remove();
    }

    // Update nav badge
    state.unreadAlerts++;
    const badge = document.getElementById('badge-alerts');
    badge.textContent = state.unreadAlerts > 99 ? '99+' : state.unreadAlerts;
    badge.style.display = 'block';
}

/**
 * Apply a category filter to the alerts list.
 * @param {'all'|'error'|'warn'|'success'} filter
 */
export function applyAlertFilter(filter) {
    state.currentFilter = filter;
    document.querySelectorAll('.chip').forEach(c => {
        c.classList.toggle('active', c.dataset.filter === filter);
    });
    state.allAlerts.forEach(({ el, type }) => {
        el.classList.toggle('hidden', filter !== 'all' && type !== filter);
    });
}

/**
 * Clear all alerts and reset the unread badge.
 */
export function clearAlerts() {
    alertsList.innerHTML = EMPTY_STATE_HTML;
    state.allAlerts = [];
    state.unreadAlerts = 0;
    document.getElementById('badge-alerts').style.display = 'none';
}
