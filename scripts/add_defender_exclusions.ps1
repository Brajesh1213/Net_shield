# ==============================================================================
# ASTHAK EDR — WINDOWS DEFENDER EXCLUSIONS
# ==============================================================================
# Because Asthak reads process memory, hooks APIs, and scans files, Windows
# Defender will likely flag it as a threat (e.g. "Behavior:Win32/Suspicious").
#
# This script adds Asthak's directories and processes to Defender's whitelist.
# ==============================================================================

Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$AsthakDir = "C:\Users\HP\Desktop\rp"
$AsthakBuildDir = "$AsthakDir\build"
$AsthakAppData = "$env:LOCALAPPDATA\Asthak"

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Asthak EDR - Adding Defender Exclusions       " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

Write-Host "[+] Adding exclusion for source code directory: $AsthakDir" -ForegroundColor Green
Add-MpPreference -ExclusionPath $AsthakDir

Write-Host "[+] Adding exclusion for build output directory: $AsthakBuildDir" -ForegroundColor Green
Add-MpPreference -ExclusionPath $AsthakBuildDir

Write-Host "[+] Adding exclusion for Quarantine/Logs directory: $AsthakAppData" -ForegroundColor Green
Add-MpPreference -ExclusionPath $AsthakAppData

Write-Host "[+] Adding exclusion for process name: Asthak.exe" -ForegroundColor Green
Add-MpPreference -ExclusionProcess "Asthak.exe"

Write-Host "`n[✓] Successfully added all required exclusions to Windows Defender." -ForegroundColor Green
Write-Host "[✓] You can view them in Windows Security -> Virus & threat protection -> Exclusions" -ForegroundColor Yellow

# Note for production:
Write-Host "`nNote: Once installed on end-user machines, Asthak will need to be submitted" -ForegroundColor Gray
Write-Host "      to the Microsoft Anti-Malware Submission portal to stop Defender from" -ForegroundColor Gray
Write-Host "      blocking it out of the box." -ForegroundColor Gray
Write-Host "      URL: https://www.microsoft.com/en-us/wdsi/filesubmission" -ForegroundColor Cyan
