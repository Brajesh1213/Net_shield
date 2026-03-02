/**
 * login.js — Login Overlay component
 * Handles form submission, session restore, session-conflict events.
 */

import { state } from './state.js';
import { appendLog } from './log.js';
import { setEngineRunning } from './engine.js';
import { handleSubscription, loadProfile } from './profile.js';

/**
 * Initialize the login overlay component.
 * Returns a { hideOverlay } helper used by main.js for auto-login.
 * @returns {{ hideOverlay: () => void }}
 */
export function initLogin() {
    const overlay    = document.getElementById('login-overlay');
    const emailInput = document.getElementById('login-email');
    const passInput  = document.getElementById('login-password');
    const submitBtn  = document.getElementById('login-submit-btn');
    const btnText    = document.getElementById('login-btn-text');
    const spinner    = document.getElementById('login-btn-spinner');
    const errorEl    = document.getElementById('login-error');

    const showError = (msg) => {
        errorEl.textContent = msg;
        errorEl.style.display = 'block';
    };

    const hideOverlay = () => {
        overlay.classList.add('hidden');
        setTimeout(() => (overlay.style.display = 'none'), 400);
    };

    const doLogin = async () => {
        const email = emailInput.value.trim();
        const pass  = passInput.value;
        if (!email || !pass) return showError('Please enter your email and password.');

        errorEl.style.display = 'none';
        submitBtn.disabled    = true;
        btnText.style.display = 'none';
        spinner.style.display = 'inline';

        const result = await window.electronAPI.loginUser(email, pass);

        submitBtn.disabled    = false;
        btnText.style.display = 'inline';
        spinner.style.display = 'none';

        if (!result.success) {
            showError(result.message || 'Login failed. Check your credentials.');
            return;
        }

        state.userEmail = email;
        hideOverlay();
        appendLog(`[AUTH] ✅ Logged in as ${email}\n`, 'success');
        handleSubscription(result.user?.subscription);

        appendLog('[AUTH] Starting protection engine…\n', 'info');
        const eng = await window.electronAPI.startBackend();
        if (eng.success) {
            setEngineRunning(true);
            appendLog('--- Asthak Engine Initialized ---\n', 'success');
        } else {
            appendLog(`[ERROR] Engine start failed: ${eng.message}\n`, 'error');
        }

        loadProfile();
    };

    // Enter key submits the form
    passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    submitBtn.addEventListener('click', doLogin);

    // Session conflict → show login again
    window.electronAPI.onSessionConflict(() => {
        overlay.style.display = 'flex';
        overlay.classList.remove('hidden');
        showError('⚠ Your account was used on another device. Please log in again.');
        appendLog('[AUTH] ⚠ Session conflict — logged out.\n', 'error');
    });

    return { hideOverlay };
}
