/**
 * engine.js — Engine Toggle component (Protection page)
 * Handles the ON / TURN OFF toggle and updates all connected UI elements.
 *
 * Blocks engine start when subscription is expired and shows a toast.
 */

import { state } from './state.js';
import { appendLog } from './log.js';
import { showToast } from './toast.js';

/**
 * Wire up the engine Start/Stop toggle buttons.
 */
export function initEngineToggle() {
    const startBtn = document.getElementById('start-btn');
    const stopBtn  = document.getElementById('stop-btn');

    startBtn.addEventListener('click', async () => {

        // ── Subscription gate ─────────────────────────────────────────────
        if (state.subscriptionStatus === 'expired') {
            showToast(
                'Your subscription has expired. Please upgrade to run the protection engine.',
                'warn',
                {
                    label: 'Upgrade Now →',
                    href:  'http://localhost:3000/pricing',
                },
                8000           // keep visible for 8 s
            );
            return;           // do NOT start the engine
        }

        // ── Normal start flow ─────────────────────────────────────────────
        startBtn.disabled = true;
        const res = await window.electronAPI.startBackend();
        if (res.success) {
            setEngineRunning(true);
            appendLog('[OK] Engine started successfully\n', 'success');
        } else {
            startBtn.disabled = false;
            appendLog(`[ERROR] Failed to start engine: ${res.message}\n`, 'error');
        }
    });

    stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true;
        stopBtn.textContent = 'STOPPING…';
        stopBtn.classList.add('stopping');
        appendLog('--- Sending stop signal to engine ---\n', 'warn');
        await window.electronAPI.stopBackend();
        // UI updates when onBackendStopped fires (max 1.5 s)
    });
}

/**
 * Sync all engine-state UI elements to the given running flag.
 * @param {boolean} running
 */
export function setEngineRunning(running) {
    state.engineRunning = running;

    const startBtn   = document.getElementById('start-btn');
    const stopBtn    = document.getElementById('stop-btn');
    const pill       = document.getElementById('engine-pill');
    const pillText   = document.getElementById('engine-pill-text');
    const protStatus = document.getElementById('prot-status');

    startBtn.disabled = running;
    stopBtn.disabled  = !running;
    stopBtn.textContent = 'TURN OFF';
    stopBtn.classList.remove('stopping');

    if (running) {
        pill.classList.add('running');
        pillText.textContent = 'Engine Active';
        protStatus.innerHTML = '<span class="status-dot active"></span> Running';
    } else {
        pill.classList.remove('running');
        pillText.textContent = 'Engine Offline';
        protStatus.innerHTML = '<span class="status-dot stopped"></span> Inactive';
    }
}
