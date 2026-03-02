# ==============================================================================
# ASTHAK EDR — GENERATE LOCAL CODE SIGNING CERTIFICATE (DEVELOPMENT)
# ==============================================================================
# This script generates a self-signed code signing certificate and installs it
# into your local Trusted Root certificate store so Windows SmartScreen will 
# trust your local builds of Asthak.
#
# NOTE: To sell this software, you MUST buy a real code signing certificate
#       from a CA like DigiCert, Sectigo, or SSL.com. This is for local dev only.
# ==============================================================================

Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

$CertName = "Asthak Security Developer Cert"
$CertStore = "Cert:\LocalMachine\My"
$RootStore = "Cert:\LocalMachine\Root"

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host " Asthak EDR - Local Code Signer Generator      " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan

# 1. Check if we already created one
$existing = Get-ChildItem -Path $CertStore | Where-Object { $_.Subject -match $CertName }
if ($existing) {
    Write-Host "[!] Found existing certificate. Deleting it to create a fresh one..." -ForegroundColor Yellow
    $existing | Remove-Item
}

# 2. Create the Self-Signed Code Signing Certificate
Write-Host "[+] Generating new Code Signing Certificate ('$CertName')..." -ForegroundColor Green
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN=$CertName" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -CertStoreLocation $CertStore `
    -NotAfter (Get-Date).AddYears(5) `
    -KeyExportPolicy Exportable

Write-Host "[+] Certificate generated! Thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

# 3. Export the certificate (without private key) to import into Trusted Root
$tempSST = "$env:TEMP\asthak_cert.sst"
Write-Host "[+] Exporting certificate temporarily..." -ForegroundColor Green
Export-Certificate -Cert $cert -FilePath $tempSST -Type SST | Out-Null

# 4. Import into Trusted Root Certification Authorities (so Windows trusts it)
Write-Host "[+] Importing into Trusted Root Certificate Authorities..." -ForegroundColor Green
Import-Certificate -FilePath $tempSST -CertStoreLocation $RootStore | Out-Null
Remove-Item $tempSST -ErrorAction SilentlyContinue

Write-Host "[+] Trusted Root import successful!" -ForegroundColor Green

# 5. Provide instructions for signing the executable
Write-Host "`n===============================================" -ForegroundColor Cyan
Write-Host " SUCCESS! You can now sign the Asthak binary.  " -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "`nTo sign your compiled Asthak.exe, run:" -ForegroundColor Yellow
Write-Host 'Set-AuthenticodeSignature -Certificate (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match "Asthak" }) -FilePath "C:\Users\HP\Desktop\rp\build\Asthak.exe" -TimestampServer "http://time.certum.pl/"'

Write-Host "`nNote: Always use a Timestamp Server so the signature stays valid forever." -ForegroundColor Gray
