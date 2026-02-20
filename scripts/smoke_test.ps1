param(
    [int]$RunSeconds = 10,
    [string]$BuildDir = "build",
    [string]$Config = "Release"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Assert([object]$Condition, [string]$Message) {
    if (-not [bool]$Condition) {
        throw "ASSERT FAILED: $Message"
    }
}

Step "Configuring project"
cmake -S . -B $BuildDir | Out-Host

Step "Building project ($Config)"
cmake --build $BuildDir --config $Config | Out-Host

$exePath = Join-Path $BuildDir "NetSentinel.exe"
Assert (Test-Path $exePath) "Executable not found at $exePath"

$tmpRoot = Join-Path $env:TEMP "netsentinel_smoke"
New-Item -ItemType Directory -Force -Path $tmpRoot | Out-Null
$stdoutPath = Join-Path $tmpRoot "stdout.txt"
$stderrPath = Join-Path $tmpRoot "stderr.txt"
Remove-Item -ErrorAction SilentlyContinue $stdoutPath, $stderrPath

Step "Starting NetSentinel for $RunSeconds second(s)"
$proc = Start-Process -FilePath $exePath -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
Start-Sleep -Seconds 1
$exitedEarly = $proc.HasExited
Start-Sleep -Seconds $RunSeconds

if (-not $proc.HasExited) {
    Step "Stopping NetSentinel process"
    Stop-Process -Id $proc.Id -Force
}

Start-Sleep -Milliseconds 300

$stdout = if (Test-Path $stdoutPath) { Get-Content -Raw $stdoutPath } else { "" }
$stderr = if (Test-Path $stderrPath) { Get-Content -Raw $stderrPath } else { "" }
$stdoutText = if ($null -eq $stdout) { "" } else { [string]$stdout }
$stderrText = if ($null -eq $stderr) { "" } else { [string]$stderr }

Step "Validating console output"
Assert (-not $exitedEarly) "Process exited too early. Check kill switch or startup failures."
if ([string]::IsNullOrWhiteSpace($stdoutText)) {
    Write-Host "Note: stdout capture is empty (common for wide-console apps)." -ForegroundColor Yellow
}

Step "Validating log file output"
$logDir = Join-Path $env:LOCALAPPDATA "NetSentinel\Logs"
$logFile = $null
if (Test-Path $logDir) {
    $today = Get-Date -Format "yyyyMMdd"
    $logFile = Join-Path $logDir ("NetSentinel_{0}.log" -f $today)
    if (Test-Path $logFile) {
        $logContent = Get-Content -Raw $logFile
        if (-not ($logContent -match "NetSentinel starting")) {
            Write-Host "Warning: log file exists but startup entry was not found." -ForegroundColor Yellow
        }
    } else {
        Write-Host "Warning: log directory exists but today's log file was not found: $logFile" -ForegroundColor Yellow
    }
} else {
    Write-Host "Warning: log directory not found (logger may have failed to initialize): $logDir" -ForegroundColor Yellow
}

Step "Smoke test passed"
Write-Host "Executable: $exePath"
Write-Host "Stdout:     $stdoutPath"
Write-Host "Stderr:     $stderrPath"
Write-Host "Log file:   $logFile"
if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
    Write-Host "`nNote: stderr was not empty:" -ForegroundColor Yellow
    Write-Host $stderrText
}
