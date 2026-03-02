/**
 * log.js — Live Engine Log component
 * appendLog, clearLog, exportLog — all operate on #log-output
 */

import { timeNow, stripAnsi } from './utils.js';

const logOutput = document.getElementById('log-output');

/**
 * Append a styled line to the live log output.
 * @param {string} text - Raw text (ANSI codes will be stripped)
 * @param {'info'|'success'|'warn'|'error'} type - CSS class for colouring
 */
export function appendLog(text, type = 'info') {
    const span = document.createElement('span');
    span.className = type;
    span.textContent = `[${timeNow()}] ${stripAnsi(text)}`;
    logOutput.appendChild(span);

    // Trim old entries to avoid unbounded growth
    if (logOutput.childNodes.length > 1500) {
        for (let i = 0; i < 300; i++) {
            if (logOutput.firstChild) logOutput.removeChild(logOutput.firstChild);
        }
    }
    logOutput.scrollTop = logOutput.scrollHeight;
}

/**
 * Clear all log entries.
 */
export function clearLog() {
    logOutput.textContent = '';
}

/**
 * Download the current log content as a .txt file.
 */
export function exportLog() {
    const blob = new Blob([logOutput.textContent], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `asthak-log-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}
