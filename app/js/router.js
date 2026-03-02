/**
 * router.js — Page navigation (sidebar nav items → page sections)
 * Lazy-loads the Network page when visited.
 */

import { loadNetworkConnections } from './network.js';

/**
 * Wire up sidebar nav buttons to show/hide page sections.
 * Also lazy-loads the Network page on first visit.
 */
export function initRouter() {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const page = document.getElementById('page-' + btn.dataset.page);
            if (page) page.classList.add('active');

            // Lazy-load network page connections on visit
            if (btn.dataset.page === 'network') loadNetworkConnections();
        });
    });
}
