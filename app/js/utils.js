/**
 * utils.js — Pure utility / helper functions
 * No DOM access — safe to import anywhere.
 */

/**
 * Strip ANSI escape codes from a string (used for C++ engine output).
 * @param {string} str
 * @returns {string}
 */
export function stripAnsi(str) {
    // eslint-disable-next-line no-control-regex
    return str.replace(/\x1B\[[0-9;]*[mGKHF]/g, '').replace(/\[[\d;]+m/g, '');
}

/**
 * Escape HTML special characters to prevent XSS.
 * @param {*} str
 * @returns {string}
 */
export function h(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

/**
 * Return current time as HH:MM:SS (24-hour).
 * @returns {string}
 */
export function timeNow() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
}
