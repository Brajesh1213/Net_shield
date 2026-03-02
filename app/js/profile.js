/**
 * profile.js — Profile page component
 * Fetches profile data via IPC and renders avatar, email, subscription badge.
 */

import { state } from './state.js';

/**
 * Load and render the user profile on the More → Profile page.
 */
export async function loadProfile() {
    const res = await window.electronAPI.getProfile();
    if (!res.success) return;

    const p      = res.profile;
    const email  = p.email || state.userEmail || '—';
    const letter = email[0]?.toUpperCase() || '?';

    document.getElementById('profile-avatar').textContent = letter;
    document.getElementById('profile-email').textContent  = email;

    const sub   = p.subscription;
    const badge = document.getElementById('profile-sub-badge');

    if (sub) {
        badge.textContent = sub.label || sub.status;
        badge.style.background =
            sub.status === 'active' ? '#dcfce7' :
            sub.status === 'beta'   ? '#dbeafe' : '#fee2e2';
        badge.style.color =
            sub.status === 'active' ? '#15803d' :
            sub.status === 'beta'   ? '#1d4ed8' : '#b91c1c';

        if (sub.message) {
            document.getElementById('profile-meta').textContent = sub.message;
        }
    }

    if (p.last_login) {
        const meta = document.getElementById('profile-meta');
        meta.textContent =
            (meta.textContent ? meta.textContent + ' · ' : '') +
            'Last login: ' + new Date(p.last_login).toLocaleString();
    }
}

/**
 * Show or hide the subscription warning banner, AND persist status to state.
 * This is the central place where subscriptionStatus is kept in sync.
 * @param {{ message?: string, status?: string, type?: string }} sub
 */
export function handleSubscription(sub) {
    if (!sub) return;

    // ── Persist to global state (engine gate reads this) ─────────────────
    if (sub.status) {
        state.subscriptionStatus = sub.status;   // 'active' | 'beta' | 'expired'
    }

    // ── Show banner only when there is a message ──────────────────────────
    if (!sub.message) return;

    const banner = document.getElementById('sub-banner');
    const msg    = document.getElementById('sub-banner-msg');
    const link   = document.getElementById('sub-banner-link');
    msg.textContent = sub.message;
    banner.style.display = 'flex';
    if (sub.status === 'expired' || sub.type === 'expired') {
        link.style.display = 'inline';
    }
}
