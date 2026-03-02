const { app, BrowserWindow, ipcMain, Tray, Menu, Notification, dialog, shell } = require('electron');
const path = require('path');
const { spawn, execSync, execFile } = require('child_process');
const http  = require('http');
const https = require('https');

const API_BASE = 'http://localhost:5000/api';

let mainWindow;
let tray = null;
let backendProcess = null;
let isQuitting = false;
let isAdmin = false;

// ── Auth session state (stored in memory, persisted in electron-store or a simple file)
let authSession = { token: null, sessionToken: null, hwid: null, email: null };

// Load saved session from disk on start
try {
    const fs = require('fs');
    const sessionPath = path.join(app.getPath('userData'), 'session.json');
    if (fs.existsSync(sessionPath)) {
        authSession = JSON.parse(fs.readFileSync(sessionPath, 'utf8'));
    }
} catch {}

const saveSession = () => {
    try {
        const fs = require('fs');
        const sessionPath = path.join(app.getPath('userData'), 'session.json');
        fs.writeFileSync(sessionPath, JSON.stringify(authSession), 'utf8');
    } catch {}
};

const clearSession = () => {
    authSession = { token: null, sessionToken: null, hwid: null, email: null };
    saveSession();
};

// ── Generate a stable HWID from machine info
const getHWID = () => {
    try {
        const os = require('os');
        const crypto = require('crypto');
        const raw = `${os.hostname()}-${os.platform()}-${os.arch()}-${os.cpus()[0]?.model}`;
        return crypto.createHash('sha256').update(raw).digest('hex').substring(0, 32);
    } catch { return 'unknown-hwid'; }
};

// ── Subscription check (polls the backend) ───────────────────────────────────
let subscriptionPollTimer = null;

const checkSubscription = async () => {
    if (!authSession.sessionToken || !authSession.hwid) return null;
    try {
        const res = await fetch(`${API_BASE}/agent/subscription`, {
            headers: {
                'X-Session-Token': authSession.sessionToken,
                'X-HWID': authSession.hwid,
            },
        });

        // Session conflict: another device logged in
        if (res.status === 409) {
            clearSession();
            if (mainWindow) mainWindow.webContents.send('session-conflict');
            if (subscriptionPollTimer) clearInterval(subscriptionPollTimer);
            return null;
        }

        if (!res.ok) return null;
        const data = await res.json();

        // Notify user if subscription is expired or about to expire
        if (data.subscription?.status === 'expired') {
            const msg = data.subscription.message || 'Your subscription has expired.';
            if (mainWindow) mainWindow.webContents.send('subscription-alert', { type: 'expired', message: msg });
            if (Notification.isSupported()) {
                new Notification({
                    title: '⚠️ Asthak — Action Required',
                    body: msg,
                }).show();
            }
        } else if (data.subscription?.status === 'beta') {
            // Only show a warning when < 7 days left
            const msg = data.subscription.message || '';
            const daysLeft = parseInt(msg.match(/(\d+) days/)?.[1]) || 999;
            if (daysLeft <= 7 && mainWindow) {
                mainWindow.webContents.send('subscription-alert', { type: 'warning', message: msg });
            }
        }

        return data.subscription;
    } catch { return null; }
};

const startSubscriptionPolling = () => {
    if (subscriptionPollTimer) clearInterval(subscriptionPollTimer);
    checkSubscription(); // immediate first check
    subscriptionPollTimer = setInterval(checkSubscription, 30 * 60 * 1000); // every 30 min
};




// ─── Admin Check ─────────────────────────────────────────────────────────────
function checkAdmin() {
    try {
        execSync('net session', { stdio: 'ignore' });
        return true;
    } catch {
        return false;
    }
}

// ─── GeoIP Cache + Lookup (via ip-api.com — free, no key needed) ─────────────
const geoipCache = new Map();
function lookupGeoIP(ip) {
    if (!ip || ip === '0.0.0.0' || ip === '*' || ip.startsWith('127.') || ip.startsWith('::')) {
        return Promise.resolve(null);
    }
    if (geoipCache.has(ip)) return Promise.resolve(geoipCache.get(ip));

    return new Promise((resolve) => {
        // ip-api.com free tier = HTTP only (HTTPS is paid)
        const req = http.get(
            `http://ip-api.com/json/${ip}?fields=status,country,countryCode,isp,proxy,hosting`,
            (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    try {
                        const info = JSON.parse(data);
                        if (info.status === 'success') {
                            geoipCache.set(ip, info);
                            resolve(info);
                        } else { resolve(null); }
                    } catch { resolve(null); }
                });
            }
        );
        req.on('error', () => resolve(null));
        req.setTimeout(3000, () => { req.destroy(); resolve(null); });
    });
}

// ─── Toast Notification ───────────────────────────────────────────────────────
function showThreatNotification(title, body) {
    if (Notification.isSupported()) {
        new Notification({ title, body, urgency: 'critical' }).show();
    }
}

// ─── Window ───────────────────────────────────────────────────────────────────
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 750,
        minWidth: 800,
        minHeight: 600,
        icon: path.join(__dirname, 'icon.png'),    // ← your icon in taskbar & Alt+Tab
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            devTools: !app.isPackaged,  
            
                       // ← DevTools off in production
        },
        frame: true,
        show: false
    });

    mainWindow.loadFile('index.html');
    mainWindow.once('ready-to-show', () => {
        mainWindow.show();
        // Tell the renderer whether we have admin rights
        isAdmin = checkAdmin();
        mainWindow.webContents.send('admin-status', isAdmin);
        // No auto-popup — user can click "Run as Admin" button in the UI
    });

    // Extra safety in packaged build: close DevTools if somehow opened
    if (app.isPackaged) {
        mainWindow.webContents.on('devtools-opened', () => {
            mainWindow.webContents.closeDevTools();
        });
    }

    mainWindow.on('close', (event) => {
        if (!isQuitting) {
            event.preventDefault();
            mainWindow.hide();
        }
    });
}

// ─── Tray ─────────────────────────────────────────────────────────────────────
function createTray() {
    try {
        tray = new Tray(path.join(__dirname, 'icon.png'));
    } catch {
        return; // icon missing — skip tray
    }
    const contextMenu = Menu.buildFromTemplate([
        { label: 'Show App', click: () => mainWindow.show() },
        { type: 'separator' },
        { label: 'Quit', click: () => { isQuitting = true; if (backendProcess) backendProcess.kill(); app.quit(); } }
    ]);
    tray.setToolTip('Asthak — Network Security Monitor');
    tray.setContextMenu(contextMenu);
    tray.on('click', () => mainWindow.isVisible() ? mainWindow.hide() : mainWindow.show());
}

// ─── App lifecycle ────────────────────────────────────────────────────────────
app.whenReady().then(() => {
    createWindow();
    createTray();
    app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
});

app.on('window-all-closed', () => { /* stay alive in tray */ });
app.on('before-quit', () => {
    isQuitting = true;
    if (backendProcess) backendProcess.kill();
});

// ─── IPC: Auth ────────────────────────────────────────────────────────────────
ipcMain.handle('auth-login', async (_, email, password) => {
    try {
        const hwid = getHWID();
        const os   = require('os');
        // 1. Login to get session_token
        const res  = await fetch(`${API_BASE}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password }),
        });
        const data = await res.json();
        if (!res.ok) return { success: false, message: data.message || 'Login failed' };

        authSession = { token: data.token, sessionToken: data.session_token, hwid, email };
        saveSession();

        // 2. Activate this device (binds HWID to session)
        await fetch(`${API_BASE}/agent/activate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_token: data.session_token,
                hwid,
                hostname:    os.hostname(),
                os_version:  `${os.type()} ${os.release()}`,
                app_version: '1.0.0-beta',
            }),
        });

        // 3. Start subscription polling
        startSubscriptionPolling();

        return { success: true, user: data.user };
    } catch (err) {
        return { success: false, message: err.message };
    }
});

ipcMain.handle('auth-logout', async () => {
    try {
        if (authSession.token) {
            await fetch(`${API_BASE}/auth/logout`, {
                method: 'POST',
                headers: { Authorization: `Bearer ${authSession.token}` },
            });
        }
    } catch {}
    clearSession();
    return { success: true };
});

ipcMain.handle('auth-get-subscription', async () => {
    return await checkSubscription();
});

// ─── IPC: Admin ───────────────────────────────────────────────────────────────
ipcMain.handle('check-admin', () => isAdmin);


ipcMain.handle('restart-as-admin', () => {
    // Build the command: in dev mode pass app dir as argument to electron.exe
    // In packaged mode, just re-run the exe
    const exePath = process.execPath;
    const appArg  = app.isPackaged ? '' : __dirname;

    try {
        // execFileSync blocks until powershell exits.
        // Start-Process -Verb RunAs shows UAC prompt.
        // If user CANCELS UAC, Start-Process throws → exit code 1 → execFileSync throws.
        // That means we catch it and keep the current app alive.
        const psArgs = appArg
            ? `Start-Process -FilePath '${exePath}' -ArgumentList '${appArg}' -Verb RunAs`
            : `Start-Process -FilePath '${exePath}' -Verb RunAs`;

        require('child_process').execFileSync(
            'powershell.exe',
            ['-NoProfile', '-NonInteractive', '-Command', psArgs],
            { stdio: 'ignore', timeout: 30000 }
        );

        // PowerShell exited without error → new elevated process is starting
        setTimeout(() => { isQuitting = true; app.quit(); }, 800);
        return { success: true };
    } catch (e) {
        // UAC was cancelled or PowerShell failed — keep the app open
        if (mainWindow) {
            mainWindow.webContents.send('backend-log',
                '[INFO] Admin restart cancelled or UAC denied. Continuing in Monitor Mode.\n');
        }
        return { success: false, message: 'UAC cancelled' };
    }
});

// ─── IPC: GeoIP ───────────────────────────────────────────────────────────────
ipcMain.handle('lookup-geoip', async (_, ip) => {
    return await lookupGeoIP(ip);
});

// ─── IPC: Backend ─────────────────────────────────────────────────────────────
ipcMain.handle('start-backend', async () => {
    if (backendProcess) return { success: false, message: 'Backend is already running.' };

    // In packaged app: electron-builder copies Asthak.exe to process.resourcesPath
    // In dev mode:     it lives at ../build/Asthak.exe relative to app/
    const exePath = app.isPackaged
        ? path.join(process.resourcesPath, 'Asthak.exe')
        : path.join(__dirname, '..', 'build', 'Asthak.exe');
    try {
        backendProcess = spawn(exePath, [], {
            stdio: ['ignore', 'pipe', 'pipe'],
            windowsHide: true
        });

        backendProcess.stdout.setEncoding('utf8');
        backendProcess.stderr.setEncoding('utf8');

        let stdoutBuf = '';
        backendProcess.stdout.on('data', (chunk) => {
            stdoutBuf += chunk;
            let idx;
            while ((idx = stdoutBuf.indexOf('\n')) !== -1) {
                const line = stdoutBuf.slice(0, idx + 1);
                stdoutBuf = stdoutBuf.slice(idx + 1);
                if (!mainWindow || !line.trim()) continue;

                mainWindow.webContents.send('backend-log', line);

                // ─── Toast notification for HIGH RISK / BLOCKED ───────────────
                const upper = line.toUpperCase();
                if (upper.includes('HIGH RISK ALERT') || upper.includes('[BLOCKED]')) {
                    const shortMsg = line.replace(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \[CRIT\] /g, '').trim();
                    showThreatNotification('🚨 Asthak Threat Detected', shortMsg.substring(0, 180));
                    mainWindow.webContents.send('threat-detected', {
                        time: new Date().toISOString(),
                        message: shortMsg,
                        isBlock: upper.includes('[BLOCKED]')
                    });
                }

                // ─── GeoIP enrichment for external IPs ───────────────────────
                const ipMatch = line.match(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/);
                if (ipMatch) {
                    const ip = ipMatch[1];
                    const isPrivate = ip.startsWith('127.') || ip.startsWith('192.168.') ||
                                      ip.startsWith('10.') || ip.startsWith('0.');
                    if (!isPrivate) {
                        lookupGeoIP(ip).then(geo => {
                            if (geo && mainWindow) {
                                const geoLine = `[GeoIP] ${ip} → ${geo.country} | ISP: ${geo.isp}${geo.proxy ? ' | ⚠ PROXY' : ''}${geo.hosting ? ' | ⚠ HOSTING' : ''}\n`;
                                mainWindow.webContents.send('backend-log', geoLine);
                            }
                        });
                    }
                }
            }
        });

        let stderrBuf = '';
        backendProcess.stderr.on('data', (chunk) => {
            stderrBuf += chunk;
            let idx;
            while ((idx = stderrBuf.indexOf('\n')) !== -1) {
                const line = stderrBuf.slice(0, idx + 1);
                stderrBuf = stderrBuf.slice(idx + 1);
                if (mainWindow && line.trim()) mainWindow.webContents.send('backend-log', line);
            }
        });

        backendProcess.on('close', (code) => {
            if (mainWindow) {
                mainWindow.webContents.send('backend-log', `Backend exited with code ${code}\n`);
                mainWindow.webContents.send('backend-stopped');
            }
            backendProcess = null;
        });

        backendProcess.on('error', (err) => {
            if (mainWindow) mainWindow.webContents.send('backend-log', `Failed to start backend: ${err.message}\n`);
            backendProcess = null;
        });

        return { success: true, message: 'Backend started.' };
    } catch (err) {
        return { success: false, message: err.message };
    }
});

ipcMain.handle('stop-backend', () => {
    if (!backendProcess) return { success: false, message: 'Backend is not running.' };
    try {
        const pid = backendProcess.pid;
        if (process.platform === 'win32') {
            try { execSync(`taskkill /F /PID ${pid} /T`, { stdio: 'ignore' }); } catch {}
        } else {
            backendProcess.kill('SIGINT');
        }
        // Force-notify the renderer after 1.5 s regardless of whether 'close' fires.
        // This handles the case where self-protection DACL delays the OS exit event.
        const bp = backendProcess;
        setTimeout(() => {
            if (backendProcess === bp) {
                backendProcess = null;
                if (mainWindow) mainWindow.webContents.send('backend-stopped');
            }
        }, 1500);
        return { success: true, message: 'Stop signal sent.' };
    } catch (err) {
        backendProcess = null;
        if (mainWindow) mainWindow.webContents.send('backend-stopped');
        return { success: false, message: err.message };
    }
});

ipcMain.handle('check-status', () => !!backendProcess);

// ─── IPC: Network stats (active connections from OS) ─────────────────────────
ipcMain.handle('get-network-stats', async () => {
    try {
        const { execSync } = require('child_process');
        const raw = execSync('netstat -ano', { encoding: 'utf8', stdio: ['ignore','pipe','ignore'] });
        const lines = raw.split('\n').filter(l => l.includes('ESTABLISHED') || l.includes('LISTENING'));
        const conns = lines.slice(0, 80).map(line => {
            const parts = line.trim().split(/\s+/);
            return { proto: parts[0], local: parts[1], remote: parts[2], state: parts[3], pid: parts[4] };
        }).filter(c => c.proto && c.local);
        return { success: true, connections: conns };
    } catch (e) {
        return { success: false, connections: [], error: e.message };
    }
});

// ─── IPC: Profile (fetch from backend with stored JWT) ────────────────────────
ipcMain.handle('auth-get-profile', async () => {
    try {
        if (!authSession.token) return { success: false };
        const res = await fetch(`${API_BASE}/auth/me`, {
            headers: { Authorization: `Bearer ${authSession.token}` }
        });
        if (!res.ok) return { success: false };
        const data = await res.json();
        return { success: true, profile: { ...data, email: authSession.email } };
    } catch { return { success: false }; }
});

