/**
 * Asthak Renderer — Structured, page-based architecture
 *
 * Pages:
 *   protection   — Engine ON/OFF + live log + stats
 *   threats      — Threat event table + timeline chart
 *   network      — Live netstat connections + GeoIP
 *   alerts       — Alert feed with filter chips
 *   more         — Profile + settings + troubleshoot
 *
 * The renderer communicates with:
 *   main.js      — via window.electronAPI (IPC)
 *   backend API  — http://localhost:5000/api (via IPC calls)
 *   C++ engine   — spawned as subprocess, logs via onBackendLog
 */

// ════════════════════════════════════════════════════════════════════════════
// CONSTANTS
// ════════════════════════════════════════════════════════════════════════════
const API_BASE = 'http://localhost:5000/api';

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: ANSI STRIPPER
// ════════════════════════════════════════════════════════════════════════════
function stripAnsi(str) {
    // eslint-disable-next-line no-control-regex
    return str.replace(/\x1B\[[0-9;]*[mGKHF]/g, '').replace(/\[[\d;]+m/g, '');
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: HTML ESCAPER
// ════════════════════════════════════════════════════════════════════════════
function h(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: TIME FORMATTER
// ════════════════════════════════════════════════════════════════════════════
function timeNow() {
    return new Date().toLocaleTimeString('en-US', { hour12: false });
}

// ════════════════════════════════════════════════════════════════════════════
// STATE (application-wide)
// ════════════════════════════════════════════════════════════════════════════
const state = {
    engineRunning:   false,
    isAdmin:         false,
    threatCount:     0,
    blockCount:      0,
    fileThreatCount: 0,
    procThreatCount: 0,
    scanCount:       0,
    alertCount:      0,
    unreadAlerts:    0,
    userEmail:       '',
    userToken:       '',
    timelineData:    Array(60).fill(0),
    timelineTick:    0,
    currentFilter:   'all',
    allAlerts:       [],   // { el, type } for filter support
};

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: PAGE ROUTER
// ════════════════════════════════════════════════════════════════════════════
function initRouter() {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
            btn.classList.add('active');
            const page = document.getElementById('page-' + btn.dataset.page);
            if (page) page.classList.add('active');

            // Lazy-load network page
            if (btn.dataset.page === 'network') loadNetworkConnections();
        });
    });
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: ENGINE TOGGLE (Protection page)
// ════════════════════════════════════════════════════════════════════════════
function initEngineToggle() {
    const startBtn = document.getElementById('start-btn');
    const stopBtn  = document.getElementById('stop-btn');

    startBtn.addEventListener('click', async () => {
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
        // UI updates when onBackendStopped fires (max 1.5s)
    });
}

function setEngineRunning(running) {
    state.engineRunning = running;

    const startBtn  = document.getElementById('start-btn');
    const stopBtn   = document.getElementById('stop-btn');
    const pill      = document.getElementById('engine-pill');
    const pillText  = document.getElementById('engine-pill-text');
    const protStatus= document.getElementById('prot-status');

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

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: LIVE LOG
// ════════════════════════════════════════════════════════════════════════════
const logOutput = document.getElementById('log-output');

function appendLog(text, type = 'info') {
    const span = document.createElement('span');
    span.className = type;
    span.textContent = `[${timeNow()}] ${stripAnsi(text)}`;
    logOutput.appendChild(span);
    // Trim
    if (logOutput.childNodes.length > 1500) {
        for (let i = 0; i < 300; i++) {
            if (logOutput.firstChild) logOutput.removeChild(logOutput.firstChild);
        }
    }
    logOutput.scrollTop = logOutput.scrollHeight;
}

function clearLog() { logOutput.textContent = ''; }

function exportLog() {
    const blob = new Blob([logOutput.textContent], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url;
    a.download = `asthak-log-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: THREAT TABLE + STATS
// ════════════════════════════════════════════════════════════════════════════
const threatsTbody = document.getElementById('threats-tbody');

function addThreatRow({ time, category, severity, detail, action }) {
    const emptyRow = threatsTbody.querySelector('.empty-row');
    if (emptyRow) emptyRow.remove();

    const severityMap = {
        critical: '<span class="sev-dot sev-crit"></span>Critical',
        high:     '<span class="sev-dot sev-high"></span>High',
        medium:   '<span class="sev-dot sev-medium"></span>Medium',
        low:      '<span class="sev-dot sev-low"></span>Low',
        info:     '<span class="sev-dot sev-info"></span>Info',
    };

    const categoryBadgeMap = {
        FILE:    '<span class="badge badge-file">FILE</span>',
        PROCESS: '<span class="badge badge-process">PROCESS</span>',
        EDR:     '<span class="badge badge-edr">EDR HOOK</span>',
        INJECT:  '<span class="badge badge-inject">INJECT</span>',
        NETWORK: '<span class="badge badge-file">NETWORK</span>',
    };

    const actionBadgeMap = {
        KILLED:   '<span class="badge badge-killed">KILLED</span>',
        BLOCKED:  '<span class="badge badge-blocked">BLOCKED</span>',
        DETECTED: '<span class="badge badge-alert">DETECTED</span>',
        HOOKED:   '<span class="badge badge-hooked">HOOKED</span>',
        ALERTED:  '<span class="badge badge-alert">ALERTED</span>',
    };

    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td style="color:#94a3b8;white-space:nowrap;font-size:11px;">${h(time)}</td>
        <td>${categoryBadgeMap[category] || `<span class="badge badge-low">${h(category)}</span>`}</td>
        <td>${severityMap[severity] || severity}</td>
        <td style="color:#475569;max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${h(detail)}</td>
        <td>${actionBadgeMap[action] || `<span class="badge badge-low">${h(action)}</span>`}</td>
    `;
    threatsTbody.insertBefore(tr, threatsTbody.firstChild);
    while (threatsTbody.rows.length > 100) threatsTbody.deleteRow(threatsTbody.rows.length - 1);

    updateThreatStats();
}

function updateThreatStats() {
    document.getElementById('th-total').textContent    = state.threatCount;
    document.getElementById('th-blocked').textContent  = state.blockCount;
    document.getElementById('th-file').textContent     = state.fileThreatCount;
    document.getElementById('th-process').textContent  = state.procThreatCount;
    document.getElementById('prot-threats').textContent = state.threatCount;
    document.getElementById('prot-blocks').textContent  = state.blockCount;
    // update nav badge
    const badge = document.getElementById('badge-threats');
    if (state.threatCount > 0) {
        badge.textContent = state.threatCount > 99 ? '99+' : state.threatCount;
        badge.style.display = 'block';
    }
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: ALERTS FEED
// ════════════════════════════════════════════════════════════════════════════
const alertsList = document.getElementById('alerts-list');

function addAlert(msg, type = 'warn', source = '') {
    // Remove empty state
    const empty = alertsList.querySelector('.empty-state');
    if (empty) empty.remove();

    const iconSvg = {
        error:   '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
        warn:    '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/></svg>',
        success: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>',
    };

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

    // Apply current filter
    applyAlertFilter(state.currentFilter);

    // Keep max 100
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

function applyAlertFilter(filter) {
    state.currentFilter = filter;
    document.querySelectorAll('.chip').forEach(c => {
        c.classList.toggle('active', c.dataset.filter === filter);
    });
    state.allAlerts.forEach(({ el, type }) => {
        el.classList.toggle('hidden', filter !== 'all' && type !== filter);
    });
}

function clearAlerts() {
    alertsList.innerHTML = '<div class="empty-state"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#cbd5e1" stroke-width="1.5"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><p>No alerts yet — system is clean ✓</p></div>';
    state.allAlerts = [];
    state.unreadAlerts = 0;
    document.getElementById('badge-alerts').style.display = 'none';
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: NETWORK MONITOR
// ════════════════════════════════════════════════════════════════════════════
const netTbody    = document.getElementById('net-tbody');
let   netRefreshing = false;

async function loadNetworkConnections() {
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
            const isEst  = c.state === 'ESTABLISHED';
            const isListen = c.state === 'LISTENING';
            if (isEst)    established++;
            if (isListen) listening++;

            // GeoIP lookup async — fill later
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

            // async GeoIP lookup
            if (remoteIp && !remoteIp.startsWith('0.') && !remoteIp.startsWith('127.') &&
                !remoteIp.startsWith('192.168.') && !remoteIp.startsWith('10.') &&
                remoteIp !== '*' && remoteIp !== '0.0.0.0') {
                window.electronAPI.lookupGeoIP(remoteIp).then(geo => {
                    const cell = document.getElementById(`geo-${tr.id}`);
                    if (!cell) return;
                    if (geo) {
                        const flagged = geo.proxy || geo.hosting;
                        cell.className = `net-geo${flagged ? ' flagged' : ''}`;
                        cell.textContent = `${geo.country}${geo.isp ? ' · ' + geo.isp.substring(0, 20) : ''}${geo.proxy ? ' ⚠PROXY' : ''}${geo.hosting ? ' ⚠HOSTING' : ''}`;
                    } else {
                        cell.textContent = '—';
                    }
                });
            } else {
                const cell = document.getElementById(`geo-${tr.id}`);
                if (cell) cell.textContent = remoteIp === '0.0.0.0' || remoteIp === '*' ? 'Local' : '—';
            }
        }

        document.getElementById('net-total').textContent       = result.connections.length;
        document.getElementById('net-established').textContent = established;
        document.getElementById('net-listening').textContent   = listening;
        document.getElementById('net-updated').textContent     = `Updated ${timeNow()}`;
    }

    if (refreshBtn) refreshBtn.innerHTML =
        '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg> Refresh';
    netRefreshing = false;
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: PROFILE PAGE
// ════════════════════════════════════════════════════════════════════════════
async function loadProfile() {
    const res = await window.electronAPI.getProfile();
    if (!res.success) return;

    const p = res.profile;
    const email  = p.email || state.userEmail || '—';
    const letter = email[0]?.toUpperCase() || '?';

    document.getElementById('profile-avatar').textContent   = letter;
    document.getElementById('profile-email').textContent    = email;

    const sub = p.subscription;
    const badge = document.getElementById('profile-sub-badge');
    if (sub) {
        badge.textContent = sub.label || sub.status;
        badge.style.background = sub.status === 'active' ? '#dcfce7' : sub.status === 'beta' ? '#dbeafe' : '#fee2e2';
        badge.style.color      = sub.status === 'active' ? '#15803d' : sub.status === 'beta' ? '#1d4ed8' : '#b91c1c';

        if (sub.message) {
            document.getElementById('profile-meta').textContent = sub.message;
        }
    }

    if (p.last_login) {
        const meta = document.getElementById('profile-meta');
        meta.textContent = (meta.textContent ? meta.textContent + ' · ' : '') +
            'Last login: ' + new Date(p.last_login).toLocaleString();
    }
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: BACKEND LOG PARSER
//   Parses every line from the C++ engine stdout and routes it to the
//   correct UI component / counter.
// ════════════════════════════════════════════════════════════════════════════
function processLogLine(rawLine) {
    const line  = stripAnsi(rawLine).trim();
    if (!line) return;

    const lower = line.toLowerCase();
    let   css   = 'info';

    // ── EDR Protective Ring hook success ──────────────────────────────
    if (lower.includes('[edr]') && lower.includes('protective ring')) {
        css = 'success';
        addThreatRow({
            time:     timeNow(),
            category: 'EDR',
            severity: 'info',
            detail:   line.replace(/\[EDR\]\s*/i, '').trim().substring(0, 120),
            action:   'HOOKED',
        });
        // Don't count as threat

    // ── File threat ───────────────────────────────────────────────────
    } else if (lower.includes('[file threat]')) {
        css = 'error';
        state.threatCount++;
        state.fileThreatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'FILE',
            severity: 'high',
            detail:   line.replace(/\[file threat\]\s*/i, '').trim().substring(0, 120),
            action:   'DETECTED',
        });
        addAlert(line, 'error', 'File Monitor');
        postAlertToBackend({ type: 'file', severity: 'high', message: line });

    // ── Process threat ────────────────────────────────────────────────
    } else if (lower.includes('[process threat]')) {
        css = 'error';
        state.threatCount++;
        state.procThreatCount++;
        state.timelineTick++;
        const isInject = lower.includes('memory injection');
        addThreatRow({
            time:     timeNow(),
            category: isInject ? 'INJECT' : 'PROCESS',
            severity: 'critical',
            detail:   line.replace(/\[process threat\]\s*/i, '').trim().substring(0, 120),
            action:   lower.includes('kill') || lower.includes('terminat') ? 'KILLED' : 'DETECTED',
        });
        addAlert(line, 'error', 'Process Monitor');
        postAlertToBackend({ type: isInject ? 'memory_injection' : 'process', severity: 'critical', message: line });

    // ── Response engine kill/block ────────────────────────────────────
    } else if (lower.includes('[responseengine] killed') || lower.includes('[blocked]')) {
        css = 'error';
        state.blockCount++;

    // ── Network threat ────────────────────────────────────────────────
    } else if (lower.includes('high risk alert') || (lower.includes('[crit]') && lower.includes('network'))) {
        css = 'error';
        state.threatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'NETWORK',
            severity: 'critical',
            detail:   line.replace(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[CRIT\]/i, '').trim().substring(0, 120),
            action:   'ALERTED',
        });
        addAlert(line, 'warn', 'Network Monitor');

    // ── Warn ──────────────────────────────────────────────────────────
    } else if (lower.includes('[warn]') || lower.includes('warning')) {
        css = 'warn';

    // ── OK / success ──────────────────────────────────────────────────
    } else if (lower.includes('[ok]') || lower.includes('initialized') || lower.includes('ready')) {
        css = 'success';
    }

    // Heartbeat → extract scan count
    const hb = line.match(/Scanned (\d+) connections/);
    if (hb) {
        state.scanCount = parseInt(hb[1], 10);
        document.getElementById('net-scanned').textContent = state.scanCount.toLocaleString();
    }

    appendLog(line + '\n', css);
    updateThreatStats();
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: BACKEND ALERT POSTER
//   Posts real threats to /api/agent/alert so they appear in the web dashboard
// ════════════════════════════════════════════════════════════════════════════
async function postAlertToBackend({ type, severity, message, remoteIp = '', process = '' }) {
    try {
        const session = await window.electronAPI.getSubscription(); // gets token from session
        // We don't have direct access to sessionToken here; it's handled server-side via headers
        // The C++ engine itself posts alerts; this is supplemental from the renderer
        await fetch(`${API_BASE}/agent/alert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ hwid: 'renderer', type, severity, message, remote_ip: remoteIp, process }),
        });
    } catch { /* best-effort */ }
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: TIMELINE CHART
// ════════════════════════════════════════════════════════════════════════════
let timelineChart;

function initChart() {
    const ctx = document.getElementById('chart-timeline')?.getContext('2d');
    if (!ctx) return;

    Chart.defaults.color = '#94a3b8';
    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{
                label: 'Threats/s',
                data: [...state.timelineData],
                borderColor: '#0d9fd8',
                backgroundColor: 'rgba(13,159,216,.10)',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.4,
                fill: true,
            }],
        },
        options: {
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: {
                    min: 0,
                    ticks: { stepSize: 1, font: { size: 10 } },
                    grid: { color: 'rgba(148,163,184,.08)' },
                },
            },
        },
    });

    // Tick every second
    setInterval(() => {
        state.timelineData.push(state.timelineTick);
        state.timelineData.shift();
        state.timelineTick = 0;
        if (timelineChart) {
            timelineChart.data.datasets[0].data = [...state.timelineData];
            timelineChart.update('none');
        }
    }, 1000);
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: ADMIN STATUS
// ════════════════════════════════════════════════════════════════════════════
function initAdminStatus() {
    const adminBadge = document.getElementById('admin-badge');
    const adminBtn   = document.getElementById('admin-btn');
    const protMode   = document.getElementById('prot-mode');

    window.electronAPI.onAdminStatus((admin) => {
        state.isAdmin = admin;
        if (admin) {
            adminBadge.textContent = '🛡 Full Protection';
            adminBadge.className = 'admin-badge ok';
            protMode.textContent = 'Full Block (Admin)';
            protMode.style.color = '#16a34a';
            adminBtn.style.display = 'none';
        } else {
            adminBadge.textContent = '⚠ Monitor Mode';
            adminBadge.className = 'admin-badge warn';
            protMode.textContent = 'Monitor Only';
        }
    });

    adminBtn.addEventListener('click', async () => {
        adminBtn.disabled = true;
        adminBtn.textContent = 'Requesting UAC…';
        const res = await window.electronAPI.restartAsAdmin();
        if (res && !res.success) {
            adminBtn.disabled = false;
            adminBtn.textContent = 'Run as Admin';
            appendLog('[INFO] Admin restart cancelled or denied.\n', 'warn');
        }
    });
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: LOGIN
// ════════════════════════════════════════════════════════════════════════════
function initLogin() {
    const overlay    = document.getElementById('login-overlay');
    const emailInput = document.getElementById('login-email');
    const passInput  = document.getElementById('login-password');
    const submitBtn  = document.getElementById('login-submit-btn');
    const btnText    = document.getElementById('login-btn-text');
    const spinner    = document.getElementById('login-btn-spinner');
    const errorEl    = document.getElementById('login-error');

    const showError = (msg) => { errorEl.textContent = msg; errorEl.style.display = 'block'; };
    const hideOverlay = () => {
        overlay.classList.add('hidden');
        setTimeout(() => overlay.style.display = 'none', 400);
    };

    const doLogin = async () => {
        const email = emailInput.value.trim();
        const pass  = passInput.value;
        if (!email || !pass) return showError('Please enter your email and password.');

        errorEl.style.display = 'none';
        submitBtn.disabled = true;
        btnText.style.display = 'none';
        spinner.style.display = 'inline';

        const result = await window.electronAPI.loginUser(email, pass);

        submitBtn.disabled = false;
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

    passInput.addEventListener('keydown', e => { if (e.key === 'Enter') doLogin(); });
    submitBtn.addEventListener('click', doLogin);

    // Session conflict
    window.electronAPI.onSessionConflict(() => {
        overlay.style.display = 'flex';
        overlay.classList.remove('hidden');
        showError('⚠ Your account was used on another device. Please log in again.');
        appendLog('[AUTH] ⚠ Session conflict — logged out.\n', 'error');
    });

    return { hideOverlay };
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: SUBSCRIPTION BANNER
// ════════════════════════════════════════════════════════════════════════════
function handleSubscription(sub) {
    if (!sub || !sub.message) return;
    const banner = document.getElementById('sub-banner');
    const msg    = document.getElementById('sub-banner-msg');
    const link   = document.getElementById('sub-banner-link');
    msg.textContent = sub.message;
    banner.style.display = 'flex';
    if (sub.status === 'expired') link.style.display = 'inline';
}

// ════════════════════════════════════════════════════════════════════════════
// COMPONENT: MISC BUTTON WIRING
// ════════════════════════════════════════════════════════════════════════════
function initMiscButtons() {
    // Log controls
    document.getElementById('clear-log-btn')?.addEventListener('click', clearLog);
    document.getElementById('export-log-btn')?.addEventListener('click', exportLog);

    // Restart engine
    const doRestart = async () => {
        appendLog('--- Restarting engine… ---\n', 'warn');
        await window.electronAPI.stopBackend();
        setTimeout(async () => {
            const res = await window.electronAPI.startBackend();
            if (res.success) { setEngineRunning(true); appendLog('--- Engine restarted ---\n', 'success'); }
        }, 2000);
    };
    document.getElementById('restart-engine-btn')?.addEventListener('click', doRestart);
    document.getElementById('more-restart-btn')?.addEventListener('click', doRestart);

    // Export
    document.getElementById('more-export-btn')?.addEventListener('click', exportLog);

    // Clear all
    const clearAll = () => {
        clearLog();
        state.threatCount = state.blockCount = state.fileThreatCount = state.procThreatCount = state.scanCount = 0;
        threatsTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No threats detected this session — engine is watching…</td></tr>';
        updateThreatStats();
    };
    document.getElementById('more-clear-btn')?.addEventListener('click', clearAll);

    // Threats clear
    document.getElementById('clear-threats-btn')?.addEventListener('click', () => {
        state.threatCount = state.blockCount = state.fileThreatCount = state.procThreatCount = 0;
        threatsTbody.innerHTML = '<tr class="empty-row"><td colspan="5">No threats detected this session — engine is watching…</td></tr>';
        document.getElementById('badge-threats').style.display = 'none';
        updateThreatStats();
    });

    // Alerts clear
    document.getElementById('clear-alerts-btn')?.addEventListener('click', clearAlerts);

    // Alert filter chips
    document.querySelectorAll('.chip').forEach(chip => {
        chip.addEventListener('click', () => applyAlertFilter(chip.dataset.filter));
    });

    // Network refresh
    document.getElementById('refresh-net-btn')?.addEventListener('click', loadNetworkConnections);

    // Logout
    document.getElementById('logout-btn')?.addEventListener('click', async () => {
        await window.electronAPI.logoutUser();
        await window.electronAPI.stopBackend();
        location.reload();
    });
}

// ════════════════════════════════════════════════════════════════════════════
// MAIN: Initialize everything
// ════════════════════════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {

    // Init all components
    initRouter();
    initEngineToggle();
    initAdminStatus();
    initChart();
    const { hideOverlay } = initLogin();
    initMiscButtons();

    // ── Auto-login (if saved session exists) ───────────────────────────
    const sub = await window.electronAPI.getSubscription();
    if (sub && sub.status !== 'expired') {
        hideOverlay();
        handleSubscription(sub);
        appendLog('[AUTH] ✅ Session restored.\n', 'success');

        const eng = await window.electronAPI.startBackend();
        if (eng.success) {
            setEngineRunning(true);
            appendLog('--- Asthak Engine Initialized ---\n', 'success');
        }
        loadProfile();
    }

    // ── Check current engine status ─────────────────────────────────────
    const running = await window.electronAPI.checkStatus();
    if (running) setEngineRunning(true);

    // ── Subscribe to engine log stream ──────────────────────────────────
    window.electronAPI.onBackendLog((data) => {
        data.split('\n').forEach(rawLine => processLogLine(rawLine));
    });

    // ── Engine stopped ──────────────────────────────────────────────────
    window.electronAPI.onBackendStopped(() => {
        setEngineRunning(false);
        appendLog('--- Engine stopped ---\n', 'warn');
    });

    // ── Threat events (from main process high-risk parser) ──────────────
    window.electronAPI.onThreatDetected((threat) => {
        state.threatCount++;
        state.timelineTick++;
        addThreatRow({
            time:     timeNow(),
            category: 'NETWORK',
            severity: 'critical',
            detail:   threat.message.substring(0, 120),
            action:   threat.isBlock ? 'BLOCKED' : 'ALERTED',
        });
        addAlert(threat.message, 'error', 'Network Monitor');
        updateThreatStats();
    });

    // ── Subscription alerts ─────────────────────────────────────────────
    window.electronAPI.onSubscriptionAlert((data) => handleSubscription(data));
});
