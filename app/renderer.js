document.addEventListener('DOMContentLoaded', async () => {
    // ── DOM refs ────────────────────────────────────────────────────────────
    const startBtn    = document.getElementById('start-btn');
    const stopBtn     = document.getElementById('stop-btn');
    const clearBtn    = document.getElementById('clear-btn');
    const adminBtn    = document.getElementById('admin-btn');
    const adminBadge  = document.getElementById('admin-badge');
    const statusDot   = document.getElementById('status-dot');
    const statusText  = document.getElementById('status-text');
    const statStatus  = document.getElementById('stat-status');
    const statEvents  = document.getElementById('stat-events');
    const statBlocks  = document.getElementById('stat-blocks');
    const statMode    = document.getElementById('stat-mode');
    const logOutput   = document.getElementById('log-output');
    // Dashboard
    const dashScans       = document.getElementById('dash-scans');
    const dashThreats     = document.getElementById('dash-threats');
    const dashBlocks      = document.getElementById('dash-blocks');
    const dashProtection  = document.getElementById('dash-protection');
    const threatsTbody    = document.getElementById('threats-tbody');
    const clearThreatsBtn = document.getElementById('clear-threats-btn');

    // ── State ───────────────────────────────────────────────────────────────
    let threatCount = 0;
    let blockCount  = 0;
    let scanCount   = 0;
    let isAdminMode = false;
    const timelineData = Array(60).fill(0);   // 1 point per second, 60s window
    let timelineThisSecond = 0;

    // ── Tabs ────────────────────────────────────────────────────────────────
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            btn.classList.add('active');
            document.getElementById(`tab-content-${btn.dataset.tab}`).classList.add('active');
        });
    });

    // ── Admin status ────────────────────────────────────────────────────────
    window.electronAPI.onAdminStatus((admin) => {
        isAdminMode = admin;
        if (admin) {
            adminBadge.textContent = '🛡 Admin — Full Protection';
            adminBadge.className = 'admin-badge full-protection';
            statMode.textContent  = 'Full Block';
            statMode.style.color  = 'var(--status-active)';
            dashProtection.textContent = 'Full Block';
            adminBtn.style.display = 'none';
        } else {
            adminBadge.textContent = '⚠ Monitor Mode';
            adminBadge.className = 'admin-badge monitor-mode';
            statMode.textContent  = 'Monitor';
            dashProtection.textContent = 'Monitor';
        }
    });

    adminBtn.addEventListener('click', async () => {
        adminBtn.disabled = true;
        adminBtn.textContent = 'Requesting UAC…';
        const res = await window.electronAPI.restartAsAdmin();
        if (res && !res.success) {
            // UAC cancelled — restore button
            adminBtn.disabled = false;
            adminBtn.textContent = 'Run as Admin';
            appendLog('[INFO] Admin restart cancelled. Running in Monitor Mode.\n', 'warn');
        }
        // If success, app will quit + reopen automatically
    });

    // ── Initial state ───────────────────────────────────────────────────────
    const running = await window.electronAPI.checkStatus();
    updateUI(running);

    // ── Buttons ─────────────────────────────────────────────────────────────
    startBtn.addEventListener('click', async () => {
        const res = await window.electronAPI.startBackend();
        if (res.success) {
            updateUI(true);
            appendLog('--- Backend Engine Initialized ---\n');
        } else {
            appendLog(`[ERROR] Failed to start: ${res.message}\n`, 'error');
        }
    });

    stopBtn.addEventListener('click', async () => {
        stopBtn.disabled = true;
        stopBtn.textContent = 'Stopping…';
        appendLog('--- Sending stop signal to engine… ---\n', 'warn');
        const res = await window.electronAPI.stopBackend();
        if (!res.success) {
            appendLog(`[INFO] ${res.message}\n`, 'warn');
            updateUI(false);
        }
    });

    clearBtn.addEventListener('click', () => {
        logOutput.textContent = '';
        threatCount = 0; blockCount = 0; scanCount = 0;
        statEvents.textContent = '0'; statBlocks.textContent = '0';
        dashScans.textContent = '0'; dashThreats.textContent = '0'; dashBlocks.textContent = '0';
    });

    clearThreatsBtn.addEventListener('click', () => {
        threatsTbody.innerHTML = '<tr class="empty-row"><td colspan="4">No threats detected yet — engine is watching…</td></tr>';
    });

    // ── Backend log stream ───────────────────────────────────────────────────
    window.electronAPI.onBackendLog((data) => {
        const lines = data.split('\n');
        lines.forEach(line => {
            if (!line.trim()) return;
            const lower = line.toLowerCase();
            let css = 'info';

            // ── File/Process threat (highest priority styling) ─────────────
            if (lower.includes('[file threat]') || lower.includes('[process threat]')) {
                css = 'error';
                threatCount++;
                statEvents.textContent = threatCount;
                dashThreats.textContent = threatCount;
                timelineThisSecond++;

                let badgeHtml = lower.includes('[file threat]')
                    ? '<span class="badge badge-file">FILE</span>'
                    : '<span class="badge badge-proc">PROCESS</span>';
                
                let detectedHtml = '<td><span class="badge badge-alert">DETECTED</span></td>';

                if (lower.includes('memory injection attack')) {
                    badgeHtml = '<span class="badge badge-high" style="background:#8b5cf6;color:white;">INJECTION</span>';
                } else if (lower.includes('edr hook injected')) {
                    badgeHtml = '<span class="badge badge-success" style="background:#10b981;color:white;">SHIELD</span>';
                    detectedHtml = '<td><span class="badge badge-success" style="background:#10b981;color:white;">HOOKED</span></td>';
                    // Don't count hooks as raw threats in the stat counter
                    threatCount--;
                    statEvents.textContent = threatCount;
                    dashThreats.textContent = threatCount;
                }

                // Also push to dashboard threats table
                const emptyRow = threatsTbody.querySelector('.empty-row');
                if (emptyRow) emptyRow.remove();
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td class="threat-time">${new Date().toLocaleTimeString()}</td>
                    <td>${badgeHtml}</td>
                    <td class="threat-msg" style="${lower.includes('edr hook') ? 'color:#10b981;' : lower.includes('memory injection') ? 'color:#c4b5fd;' : ''}">${escapeHtml(line.replace(/\[.*?\]\s*/g,'').trim().substring(0,105))}</td>
                    ${detectedHtml}
                `;
                threatsTbody.insertBefore(tr, threatsTbody.firstChild);
                while (threatsTbody.rows.length > 50) threatsTbody.deleteRow(threatsTbody.rows.length - 1);
                updateBreakdownChart();

            } else if (lower.includes('[blocked]') || lower.includes('terminated')) {
                css = 'error';
                blockCount++;
                statBlocks.textContent = blockCount;
                dashBlocks.textContent = blockCount;
            } else if (lower.includes('high risk') || lower.includes('critical') || lower.includes('[warn]')) {
                css = 'warn';
            } else if (lower.includes('[ok]') || lower.includes('low ')) {
                css = 'success';
            }

            // heartbeat → extract scan count
            const hbMatch = line.match(/Scanned (\d+) connections/);
            if (hbMatch) {
                scanCount = parseInt(hbMatch[1], 10);
                dashScans.textContent = scanCount.toLocaleString();
            }

            appendLog(line + '\n', css);
        });
    });


    // ── Threat events (from main process) ───────────────────────────────────
    window.electronAPI.onThreatDetected((threat) => {
        threatCount++;
        statEvents.textContent = threatCount;
        dashThreats.textContent = threatCount;
        timelineThisSecond++;

        // Add row to threats table
        const emptyRow = threatsTbody.querySelector('.empty-row');
        if (emptyRow) emptyRow.remove();

        const tr = document.createElement('tr');
        const t = new Date(threat.time);
        const timeStr = t.toLocaleTimeString();
        const actionLabel = threat.isBlock
            ? '<span class="badge badge-block">BLOCKED</span>'
            : '<span class="badge badge-alert">DETECTED</span>';

        tr.innerHTML = `
            <td class="threat-time">${timeStr}</td>
            <td><span class="badge badge-high">HIGH</span></td>
            <td class="threat-msg">${escapeHtml(threat.message.substring(0, 90))}</td>
            <td>${actionLabel}</td>
        `;
        threatsTbody.insertBefore(tr, threatsTbody.firstChild);

        // Keep max 50 rows
        while (threatsTbody.rows.length > 50) threatsTbody.deleteRow(threatsTbody.rows.length - 1);

        // Update breakdown chart
        updateBreakdownChart();
    });

    window.electronAPI.onBackendStopped(() => {
        updateUI(false);
        stopBtn.textContent = 'Stop Engine';
        appendLog('--- Backend Engine Process Terminated ---\n');
    });

    // ── UI helpers ───────────────────────────────────────────────────────────
    function updateUI(running) {
        startBtn.disabled = running;
        stopBtn.disabled  = !running;
        statusDot.className = `dot ${running ? 'active' : 'stopped'}`;
        statusText.textContent  = running ? 'Engine Active'   : 'Engine Inactive';
        statusText.style.color  = `var(${running ? '--status-active' : '--status-inactive'})`;
        statStatus.textContent  = running ? 'Running'         : 'Down';
        statStatus.style.color  = `var(${running ? '--status-active' : '--status-inactive'})`;
        if (!running) stopBtn.textContent = 'Stop Engine';
    }

    function appendLog(text, type = 'info') {
        const span = document.createElement('span');
        span.className = type;
        const now = new Date();
        span.textContent = `[${now.toLocaleTimeString()}] ${text}`;
        logOutput.appendChild(span);
        // Trim old entries
        if (logOutput.childNodes.length > 2000) {
            for (let i = 0; i < 500; i++) logOutput.removeChild(logOutput.firstChild);
        }
        logOutput.parentElement.scrollTop = logOutput.parentElement.scrollHeight;
    }

    function escapeHtml(str) {
        return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    // ── Chart.js setup ───────────────────────────────────────────────────────
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = 'rgba(148,163,184,0.08)';

    // Timeline chart
    const timelineCtx = document.getElementById('chart-timeline').getContext('2d');
    const timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{
                label: 'Threats/s',
                data: timelineData,
                borderColor: '#f87171',
                backgroundColor: 'rgba(248,113,113,0.12)',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false }, tooltip: { mode: 'index', intersect: false } },
            scales: {
                x: { display: false },
                y: { min: 0, ticks: { stepSize: 1 }, grid: { color: 'rgba(148,163,184,0.08)' } }
            }
        }
    });

    // Breakdown doughnut chart
    const breakdownCtx = document.getElementById('chart-breakdown').getContext('2d');
    const breakdownChart = new Chart(breakdownCtx, {
        type: 'doughnut',
        data: {
            labels: ['Detected', 'Blocked'],
            datasets: [{
                data: [0, 0],
                backgroundColor: ['#fbbf24', '#f87171'],
                borderColor: '#1e293b',
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { padding: 16 } }
            },
            cutout: '65%'
        }
    });

    function updateBreakdownChart() {
        const detected = Math.max(0, threatCount - blockCount);
        breakdownChart.data.datasets[0].data = [detected, blockCount];
        breakdownChart.update('none');
    }

    // Timeline ticker — shift left every second
    setInterval(() => {
        timelineData.push(timelineThisSecond);
        timelineData.shift();
        timelineThisSecond = 0;
        timelineChart.data.datasets[0].data = [...timelineData];
        timelineChart.update('none');
    }, 1000);
});
