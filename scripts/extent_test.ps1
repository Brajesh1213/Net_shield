param(
    [string]$BuildDir = "build",
    [string]$Config = "Release",
    [int]$RunSeconds = 12,
    [int]$WarmupSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Step([string]$Message) { Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Ok([string]$Message) { Write-Host "  [OK]  $Message" -ForegroundColor Green }
function Warn([string]$Message) { Write-Host "  [WARN] $Message" -ForegroundColor Yellow }
function Fail([string]$Message) { Write-Host "  [FAIL] $Message" -ForegroundColor Red }

function Get-TodaysLogFile() {
    $logDir = Join-Path $env:LOCALAPPDATA "NetSentinel\Logs"
    $today = Get-Date -Format "yyyyMMdd"
    $logFile = Join-Path $logDir ("NetSentinel_{0}.log" -f $today)
    return [pscustomobject]@{ Dir = $logDir; File = $logFile }
}

function Tail([string]$Path, [int]$Lines = 80) {
    if (-not (Test-Path $Path)) { return "" }
    try { return (Get-Content $Path -Tail $Lines -ErrorAction Stop) -join "`n" } catch { return "" }
}

function Find-InText([string]$Text, [string]$Pattern) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    return [bool]([regex]::Match($Text, $Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase))
}

Step "Build (CMake configure + build)"
cmake -S . -B $BuildDir | Out-Host
cmake --build $BuildDir --config $Config | Out-Host

$exePath = Join-Path $BuildDir "NetSentinel.exe"
if (-not (Test-Path $exePath)) {
    Fail "Executable not found: $exePath"
    exit 1
}
Ok "Executable exists: $exePath"

# Clean up old log evidence (only today's file) so results are fresh
$logInfo = Get-TodaysLogFile
if (Test-Path $logInfo.File) {
    Step "Removing today's old log file (fresh test)"
    Remove-Item -Force $logInfo.File
}

Step "Start NetSentinel (background)"
$tmpRoot = Join-Path $env:TEMP "netsentinel_extent"
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
$stdoutPath = Join-Path $tmpRoot "stdout.txt"
$stderrPath = Join-Path $tmpRoot "stderr.txt"
Remove-Item -ErrorAction SilentlyContinue $stdoutPath, $stderrPath

$env:NETSENTINEL_TEST_MODE = "1"
$proc = Start-Process -FilePath $exePath -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
Start-Sleep -Seconds $WarmupSeconds

if ($proc.HasExited) {
    $stderr = if (Test-Path $stderrPath) { Get-Content -Raw $stderrPath } else { "" }
    Fail "NetSentinel exited early (exit code: $($proc.ExitCode)). Kill switch or startup failure."
    if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        Warn "Stderr:"
        Write-Host $stderr
    }
    exit 2
}
Ok "NetSentinel is running (PID: $($proc.Id))"

Step "Generate live test traffic (TCP + UDP)"

# TCP: offline/local reliable test on suspicious port 4444 (loopback allowed in test mode)
try {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 4444)
    $listener.Start()
    $acceptJob = Start-Job -ScriptBlock {
        param($l)
        try {
            $client = $l.AcceptTcpClient()
            Start-Sleep -Seconds 6
            $client.Close()
        } catch {}
    } -ArgumentList $listener

    $client = [System.Net.Sockets.TcpClient]::new()
    $client.Connect("127.0.0.1", 4444)
    Ok "Created local TCP connection: 127.0.0.1:4444 (suspicious port)"
    Start-Sleep -Seconds 4
    $client.Close()

    $listener.Stop()
    Receive-Job $acceptJob -Wait | Out-Null
    Remove-Job $acceptJob -Force | Out-Null
} catch {
    Warn "Local TCP test failed: $($_.Exception.Message)"
}

# UDP: bind locally and send to loopback (offline reliable)
try {
    $udp = New-Object System.Net.Sockets.UdpClient(0)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes("netsentinel-udp-test")
    [void]$udp.Send($bytes, $bytes.Length, "127.0.0.1", 5353)
    $udp.Close()
    Ok "Sent UDP test datagram to 127.0.0.1:5353"
} catch {
    Warn "UDP send failed: $($_.Exception.Message)"
}

Step "Let NetSentinel analyze for $RunSeconds second(s)"
Start-Sleep -Seconds $RunSeconds

Step "Stop NetSentinel"
if (-not $proc.HasExited) {
    Stop-Process -Id $proc.Id -Force
    Start-Sleep -Milliseconds 300
}
Ok "Stopped"

Step "Evaluate extent (what worked)"
$stderrText = if (Test-Path $stderrPath) { [string](Get-Content -Raw $stderrPath) } else { "" }
if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
    Warn "Non-empty stderr (may be ok):"
    Write-Host $stderrText
}

if (-not (Test-Path $logInfo.Dir)) {
    Fail "Logs directory not created: $($logInfo.Dir)"
    Fail "This usually means logger init failed."
    exit 3
}
Ok "Logs directory exists: $($logInfo.Dir)"

if (-not (Test-Path $logInfo.File)) {
    Fail "Today's log file not found: $($logInfo.File)"
    exit 4
}
Ok "Today's log file exists: $($logInfo.File)"

$tail = Tail $logInfo.File 200

# Core signals
$hasStartup = Find-InText $tail "NetSentinel starting"
$hasMedium = Find-InText $tail "\[MEDIUM RISK\]"
$hasHighAlert = Find-InText $tail "HIGH RISK|HIGH RISK ALERT"
$hasKillSwitch = Find-InText $tail "Kill switch activated|DISABLED via kill switch"

Write-Host "`n--- Capability Matrix (detected from logs) ---"
if ($hasStartup) { Ok "Logging: startup entry found" } else { Warn "Logging: startup entry not found (but file exists)" }

if ($hasMedium -or $hasHighAlert) {
    Ok "Live traffic monitoring: detections logged (MEDIUM/HIGH present)"
} else {
    Warn "Live traffic monitoring: no MEDIUM/HIGH detections observed in this run"
    Warn "Tip: run again while browsing web or using maintain_connections.py"
}

# UDP extent: we can't reliably prove UDP remote endpoints from the table, but we can at least state availability.
Write-Host ""
Warn "UDP extent note: UDP table shows local endpoints only (often remote IP/port is unavailable)."

Write-Host "`n--- Log tail (last 40 lines) ---"
Write-Host (Tail $logInfo.File 40)

Write-Host "`nDone."
