/**
 * toast.js — In-app Toast Notification component
 *
 * Shows a slide-in toast in the bottom-right corner.
 * Auto-dismisses after `duration` ms (default 6 s).
 *
 * Usage:
 *   showToast('Your subscription has expired.', 'warn', {
 *       label: 'Upgrade Now',
 *       href: 'http://localhost:3000/pricing',
 *   });
 */

// Ensure the container exists once
let _container = null;
function _getContainer() {
    if (!_container) {
        _container = document.createElement('div');
        _container.id = 'toast-container';
        document.body.appendChild(_container);
    }
    return _container;
}

/**
 * Show a toast notification.
 * @param {string}  message  - Main toast message
 * @param {'info'|'warn'|'error'|'success'} type
 * @param {{ label: string, href?: string, onClick?: Function } | null} action
 * @param {number}  duration - Auto-dismiss delay in ms (default 6000)
 */
export function showToast(message, type = 'warn', action = null, duration = 6000) {
    const container = _getContainer();

    const icons = {
        error:   `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>`,
        warn:    `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        success: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>`,
        info:    `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>`,
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;

    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.warn}</div>
        <div class="toast-body">
            <div class="toast-msg">${_escHtml(message)}</div>
            ${action ? `<div class="toast-action-wrap"></div>` : ''}
        </div>
        <button class="toast-close" aria-label="Dismiss">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
        </button>
        <div class="toast-progress"></div>
    `;

    // Wire up action button / link
    if (action) {
        const wrap = toast.querySelector('.toast-action-wrap');
        if (action.href) {
            const a = document.createElement('a');
            a.className = 'toast-action-link';
            a.textContent = action.label;
            a.href = action.href;
            a.target = '_blank';
            wrap.appendChild(a);
        } else if (action.onClick) {
            const btn = document.createElement('button');
            btn.className = 'toast-action-link';
            btn.textContent = action.label;
            btn.addEventListener('click', () => { dismiss(); action.onClick(); });
            wrap.appendChild(btn);
        }
    }

    // Dismiss helpers
    let timer;
    const dismiss = () => {
        clearTimeout(timer);
        toast.classList.add('toast-out');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
    };

    toast.querySelector('.toast-close').addEventListener('click', dismiss);
    timer = setTimeout(dismiss, duration);

    // Animate progress bar
    const prog = toast.querySelector('.toast-progress');
    prog.style.animationDuration = `${duration}ms`;
    prog.classList.add('toast-progress-run');

    container.appendChild(toast);

    // Trigger enter animation
    requestAnimationFrame(() => toast.classList.add('toast-in'));

    return { dismiss };
}

function _escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}
