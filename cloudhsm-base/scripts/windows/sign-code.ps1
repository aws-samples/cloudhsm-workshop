<#
.SYNOPSIS    Signs & verifies a file using CloudHSM‑backed cert.
.PARAMETER   FilePath
.PARAMETER   CertificateThumbprint
.PARAMETER   TimestampServer
#>
param(
    [Parameter(Mandatory=$true)][ValidateScript({Test-Path $_})] [string]$FilePath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9A-Fa-f]{40}$')] [string]$CertificateThumbprint,
    [Parameter(Mandatory=$false)]                   [string]$TimestampServer = "http://timestamp.digicert.com"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# locate signtool.exe
$signtool = $null
$preferredPath = "C:\CloudHSM\signing-tools\signtool.exe"

if (Test-Path $preferredPath) {
    $signtool = Get-Item $preferredPath
    Write-Host "Using SignTool from preferred path: $($signtool.FullName)"
} else {
    Write-Host "SignTool not found in preferred path ($preferredPath). Searching Windows SDK..."
    $paths = @(
        "$Env:ProgramFiles(x86)\Windows Kits\10\bin\*\x64\signtool.exe",
        "$Env:ProgramFiles(x86)\Windows Kits\10\bin\*\x86\signtool.exe",
        "$Env:ProgramFiles(x86)\Windows Kits\8.1\bin\x64\signtool.exe", # Added 8.1 for broader compatibility
        "$Env:ProgramFiles(x86)\Windows Kits\8.1\bin\x86\signtool.exe"  # Added 8.1 for broader compatibility
    )
    $signtool = Get-ChildItem -Path $paths -ErrorAction SilentlyContinue | Select-Object -First 1
}

if (-not $signtool) { throw "signtool.exe not found in preferred path or Windows SDK." }
Write-Host "Using SignTool: $($signtool.FullName)"

# Verify CloudHSM KSP is registered
$kspPath = "C:\Program Files\Amazon\CloudHSM\bin\cloudhsm-ksp.dll"
# PSScriptAnalyzer disable PSUseDeclaredVarsMoreThanAssignments - justification: $kspPath is used in the following Test-Path
if (-not (Test-Path $kspPath)) { throw "CloudHSM KSP not found. Please run setup-cloudhsm.ps1 first." }
# PSScriptAnalyzer enable PSUseDeclaredVarsMoreThanAssignments

# Verify certificate exists and is accessible
try {
    $cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
    if (-not $cert) { throw "Certificate with thumbprint $CertificateThumbprint not found in LocalMachine\My store" }
} catch {
    throw "Error accessing certificate store: $_. Ensure script runs with administrator privileges."
}

# Verify certificate has an associated private key accessible to the current user
if (-not $cert.HasPrivateKey) { throw "Certificate with thumbprint $CertificateThumbprint found, but its private key is not accessible. Ensure the script runs with appropriate permissions." }

# Verify the private key is not null (additional check)
if ($null -eq $cert.PrivateKey) { throw "Certificate with thumbprint $CertificateThumbprint found, but its private key object is null. This might indicate a problem with the certificate store or permissions." }

# Verify certificate is using CloudHSM KSP
try {
    Write-Verbose "Checking provider for certificate '$($cert.Subject)' (Thumbprint: $CertificateThumbprint)"
    Write-Verbose "Provider Name: $($cert.PrivateKey.CspKeyContainerInfo.ProviderName)"
    if ($cert.PrivateKey.CspKeyContainerInfo.ProviderName -ne "CloudHSM Key Storage Provider") { 
        throw "Certificate is not using CloudHSM KSP ('CloudHSM Key Storage Provider'). Found provider: '$($cert.PrivateKey.CspKeyContainerInfo.ProviderName)'. Please ensure the certificate was generated or imported correctly using CloudHSM tools." 
    }
} catch {
    if ($_.Exception.Message -match "CloudHSM KSP") { throw $_ }
    throw "Error accessing certificate provider information: $_. Verify the certificate's Key Storage Provider."
}

Write-Host "Signing $FilePath"
& $signtool.FullName sign /v /sm /sha1 $CertificateThumbprint /fd sha256 /tr $TimestampServer /td sha256 $FilePath;
if ($LASTEXITCODE -ne 0) {
    throw "Signing failed."
}

Write-Host "Verifying signature"
& $signtool.FullName verify /v /pa $FilePath;
if ($LASTEXITCODE -ne 0) {
    throw "Verification failed."
}

Write-Host "File signed & verified successfully."
