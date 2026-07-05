<#
.SYNOPSIS
    Creates a self-signed certificate for authenticating an Entra app registration
    (for use with Micke-K/IntuneManagement app-login), keeping the PRIVATE key in the
    current user's certificate store and exporting ONLY the PUBLIC key (.cer) for upload.

.DESCRIPTION
    - Private key: created in Cert:\CurrentUser\My (never leaves the machine).
    - Public key : exported as .cer to upload to the app registration > Certificates & secrets.
    - Optional   : also export a password-protected .pfx (private key) for backup to an
                   OFFLINE, secured location only. Off by default. Handle with care.

    Auth model note: IntuneManagement uses DELEGATED Graph permissions even when logging
    in "as the app" with this certificate. Configure the app registration's Graph
    permissions under Delegated (read-only for a backup identity) and grant admin consent.

.PARAMETER Subject
    Certificate subject / friendly name. Default: CN=IntuneManagement-Backup

.PARAMETER ValidYears
    Validity in years. Default: 2. (Rotate before expiry; note the date.)

.PARAMETER ExportPfx
    Switch. If set, ALSO exports a password-protected .pfx (private key backup).
    Only do this if you need a secure offline backup of the key. You will be prompted
    for a password.

.PARAMETER OutputFolder
    Where to write the .cer (and optional .pfx). Default: current folder.

.EXAMPLE
    .\New-IntuneMgmtAppCertificate.ps1
    Creates the cert, exports IntuneManagement-Backup.cer to the current folder.

.EXAMPLE
    .\New-IntuneMgmtAppCertificate.ps1 -Subject "CN=IM-Backup-BaselineTenant" -ValidYears 1 -ExportPfx
    Creates a 1-year cert with a custom name and also exports a protected .pfx backup.

.NOTES
    Requires: Windows PowerShell 5.1+ or PowerShell 7 on Windows (uses PKI module /
    New-SelfSignedCertificate, which is Windows-only).
    Reference: Entra app cert auth — https://learn.microsoft.com/entra/identity-platform/howto-create-self-signed-certificate
#>

[CmdletBinding()]
param(
    [string]$Subject       = "CN=IntuneManagement-Backup",
    [int]   $ValidYears    = 2,
    [switch]$ExportPfx,
    [string]$OutputFolder  = (Get-Location).Path
)

$ErrorActionPreference = 'Stop'

# Derive a safe file base name from the subject (strip 'CN=' and non-filename chars)
$baseName = ($Subject -replace '^CN=','') -replace '[^A-Za-z0-9_.-]','_'
$cerPath  = Join-Path $OutputFolder "$baseName.cer"
$pfxPath  = Join-Path $OutputFolder "$baseName.pfx"

if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }

Write-Host "Creating self-signed certificate..." -ForegroundColor Cyan
Write-Host "  Subject   : $Subject"
Write-Host "  Validity  : $ValidYears year(s)"
Write-Host "  Key store : Cert:\CurrentUser\My (private key stays here)"

# Create the certificate. Key stays in CurrentUser\My.
# KeySpec Signature + SHA256 is what Entra expects for app credential certs.
$cert = New-SelfSignedCertificate `
    -Subject           $Subject `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyExportPolicy   Exportable `
    -KeySpec           Signature `
    -KeyLength         2048 `
    -HashAlgorithm     SHA256 `
    -NotAfter          (Get-Date).AddYears($ValidYears) `
    -Provider          "Microsoft Enhanced RSA and AES Cryptographic Provider"

Write-Host "`nCertificate created." -ForegroundColor Green
Write-Host "  Thumbprint: $($cert.Thumbprint)" -ForegroundColor Yellow
Write-Host "  (You will pass this thumbprint to IntuneManagement via -Certificate)"

# Export PUBLIC key only (.cer) -> this is what you upload to the app registration.
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
Write-Host "`nPublic key exported (upload THIS to the app registration):" -ForegroundColor Green
Write-Host "  $cerPath"

# Optionally export a protected PFX (PRIVATE key) for secure OFFLINE backup only.
if ($ExportPfx) {
    Write-Host "`nExporting password-protected .pfx (PRIVATE key backup)..." -ForegroundColor Cyan
    $pfxPwd = Read-Host "Enter a strong password for the .pfx" -AsSecureString
    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pfxPwd | Out-Null
    Write-Host "  $pfxPath" -ForegroundColor Green
    Write-Host "  WARNING: This file contains the PRIVATE key. Store it offline/secured and delete working copies." -ForegroundColor Red
}

Write-Host "`n--- Next steps ---" -ForegroundColor White
Write-Host "1. Entra portal > App registrations > (your backup app) > Certificates & secrets"
Write-Host "   > Certificates > Upload certificate > select: $cerPath"
Write-Host "2. Confirm the uploaded thumbprint matches: $($cert.Thumbprint)"
Write-Host "3. Under API permissions, add Microsoft Graph *Delegated* read scopes and Grant admin consent."
Write-Host "4. Launch the tool as the app:"
Write-Host "   .\Start-IntuneManagement.ps1 -TenantId '<TenantId>' -AppId '<AppId>' -Certificate '$($cert.Thumbprint)' -ShowConsoleWindow"
Write-Host ""