# NetSentinel Manual Test Checklist

## 1. Build
Run:
```powershell
cmake -S . -B build
cmake --build build --config Release
```
Pass:
- Build completes without errors.
- `build\NetSentinel.exe` exists.

## 2. Smoke Run
Run:
```powershell
.\build\NetSentinel.exe
```
Pass:
- Banner includes `NetSentinel`.
- Table header appears (`TIME | PROCESS | ...`).
- App stays running and updates periodically.
- `Ctrl+C` stops cleanly.

## 3. Logging
Run app for 15-30 seconds, then check:
```powershell
Get-ChildItem "$env:LOCALAPPDATA\NetSentinel\Logs"
```
Pass:
- A file named `NetSentinel_YYYYMMDD.log` exists.
- Log contains startup/shutdown entries.

## 4. Kill Switch
Disable:
```powershell
reg add HKCU\Software\CyberGuardian\NetSentinel /v DisableMonitoring /t REG_DWORD /d 1 /f
.\build\NetSentinel.exe
```
Pass:
- App exits immediately with disabled message.

Re-enable:
```powershell
reg delete HKCU\Software\CyberGuardian\NetSentinel /v DisableMonitoring /f
```

## 5. Risk Signal Sanity
While NetSentinel runs:
```powershell
Test-NetConnection 1.1.1.1 -Port 443
Test-NetConnection 127.0.0.1 -Port 4444
```
Pass:
- 443 traffic is generally not flagged high.
- Suspicious port traffic (for example 4444) can appear as elevated risk.

## 6. Admin/Non-Admin Behavior
Run once in standard shell and once in elevated shell.
Pass:
- Non-admin run shows warning about limited visibility.
- Elevated run reduces unknown process entries.

## Optional: one-command smoke test
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\smoke_test.ps1
```
