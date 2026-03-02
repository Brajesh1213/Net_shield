/**
 * network.js — Network Monitor component (Network page)
 * Loads active connections via IPC, renders the table, and makes GeoIP lookups.
 */

import { h, timeNow } from './utils.js';

const netTbody = document.getElementById('net-tbody');
let   netRefreshing = false;

/**
 * Fetch and render the live network connections table.
 * Called on first visit to the Network page and on Refresh button click.
 */
export async function loadNetworkConnections() {
    if (netRefreshing) return;
    netRefreshing = true;

    const refreshBtn = document.getElementById('refresh-net-btn');
    if (refreshBtn) refreshBtn.textContent = 'Loading…';

    const result = await window.electronAPI.getNetworkStats();
    netTbody.innerHTML = '';

    if (!result.success || result.connections.length === 0) {
        netTbody.innerHTML = '<tr class="empty-row"><td colspan="6">No connections found</td></tr>';
    } else {
        let established = 0, listening = 0;

        for (const c of result.connections) {
            const isEst    = c.state === 'ESTABLISHED';
            const isListen = c.state === 'LISTENING';
            if (isEst)    established++;
            if (isListen) listening++;

            const tr = document.createElement('tr');
            tr.id = `net-row-${c.pid}-${c.remote || 'x'}`.replace(/[^a-z0-9-]/gi, '_');

            const stateClass = isEst ? 'net-established' : isListen ? 'net-listening' : 'net-other';
            const remoteIp   = (c.remote || '').split(':')[0];

            tr.innerHTML = `
                <td><span class="badge badge-low">${h(c.proto || '—')}</span></td>
                <td class="net-local">${h(c.local || '—')}</td>
                <td class="net-remote">${h(c.remote || '—')}</td>
                <td class="${stateClass}">${h(c.state || '—')}</td>
                <td style="color:#94a3b8;font-size:11px;">${h(c.pid || '—')}</td>
                <td class="net-geo" id="geo-${tr.id}">…</td>
            `;
            netTbody.appendChild(tr);

            // Async GeoIP lookup (skip private/local IPs)
            _lookupGeoIP(remoteIp, tr.id);
        }

        document.getElementById('net-total').textContent       = result.connections.length;
        document.getElementById('net-established').textContent = established;
        document.getElementById('net-listening').textContent   = listening;
        document.getElementById('net-updated').textContent     = `Updated ${timeNow()}`;
    }

    if (refreshBtn) {
        refreshBtn.innerHTML =
            '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Refresh';
    }
    netRefreshing = false;
}

// ── Private helpers ────────────────────────────────────────────────────────

/**
 * Resolve GeoIP for a remote IP and fill the table cell.
 * Skips private/broadcast addresses.
 * @param {string} remoteIp
 * @param {string} rowId - used to find the geo-<rowId> cell
 */
function _lookupGeoIP(remoteIp, rowId) {
    const isPrivate =
        !remoteIp ||
        remoteIp.startsWith('0.') ||
        remoteIp.startsWith('127.') ||
        remoteIp.startsWith('192.168.') ||
        remoteIp.startsWith('10.') ||
        remoteIp === '*' ||
        remoteIp === '0.0.0.0';

    const cell = document.getElementById(`geo-${rowId}`);

    if (isPrivate) {
        if (cell) cell.textContent = remoteIp === '0.0.0.0' || remoteIp === '*' ? 'Local' : '—';
        return;
    }

    window.electronAPI.lookupGeoIP(remoteIp).then(geo => {
        if (!cell) return;
        if (geo) {
            const flagged = geo.proxy || geo.hosting;
            cell.className = `net-geo${flagged ? ' flagged' : ''}`;
            cell.textContent =
                `${geo.country}${geo.isp ? ' · ' + geo.isp.substring(0, 20) : ''}` +
                `${geo.proxy ? ' ⚠PROXY' : ''}${geo.hosting ? ' ⚠HOSTING' : ''}`;
        } else {
            cell.textContent = '—';
        }
    });
}
