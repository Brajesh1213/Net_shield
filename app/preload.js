const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    startBackend:      () => ipcRenderer.invoke('start-backend'),
    stopBackend:       () => ipcRenderer.invoke('stop-backend'),
    checkStatus:       () => ipcRenderer.invoke('check-status'),
    checkAdmin:        () => ipcRenderer.invoke('check-admin'),
    restartAsAdmin:    () => ipcRenderer.invoke('restart-as-admin'),
    lookupGeoIP:       (ip) => ipcRenderer.invoke('lookup-geoip', ip),
    onBackendLog:      (cb) => ipcRenderer.on('backend-log',     (_, d) => cb(d)),
    onBackendStopped:  (cb) => ipcRenderer.on('backend-stopped', ()    => cb()),
    onThreatDetected:  (cb) => ipcRenderer.on('threat-detected', (_, d) => cb(d)),
    onAdminStatus:     (cb) => ipcRenderer.on('admin-status',    (_, d) => cb(d)),
});
