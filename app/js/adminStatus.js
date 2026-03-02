/**
 * adminStatus.js — Admin badge + protection mode indicator
 * Listens to onAdminStatus IPC event and updates the topbar badge.
 */

import { state } from './state.js';
import { appendLog } from './log.js';

/**
 * Wire up the admin badge and "Run as Admin" button in the topbar.
 */
export function initAdminStatus() {
    const adminBadge = document.getElementById('admin-badge');
    const adminBtn   = document.getElementById('admin-btn');
    const protMode   = document.getElementById('prot-mode');

    window.electronAPI.onAdminStatus((admin) => {
        state.isAdmin = admin;
        if (admin) {
            adminBadge.textContent = '🛡 Full Protection';
            adminBadge.className   = 'admin-badge ok';
            protMode.textContent   = 'Full Block (Admin)';
            protMode.style.color   = '#16a34a';
            adminBtn.style.display = 'none';
        } else {
            adminBadge.textContent = '⚠ Monitor Mode';
            adminBadge.className   = 'admin-badge warn';
            protMode.textContent   = 'Monitor Only';
        }
    });

    adminBtn.addEventListener('click', async () => {
        adminBtn.disabled    = true;
        adminBtn.textContent = 'Requesting UAC…';
        const res = await window.electronAPI.restartAsAdmin();
        if (res && !res.success) {
            adminBtn.disabled    = false;
            adminBtn.textContent = 'Run as Admin';
            appendLog('[INFO] Admin restart cancelled or denied.\n', 'warn');
        }
    });
}
