<#
.SYNOPSIS    Generates a CSR via CloudHSM KSP.
.PARAMETER   ClusterId
.PARAMETER   Region
#>
param(
    [Parameter(Mandatory=$false)] [string]$ClusterId,
    [Parameter(Mandatory=$false)] [string]$Region
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$dir = "C:\CloudHSM"

# Check for ClusterId in file if not provided as parameter
if (-not $ClusterId) {
    if (Test-Path "$dir\cluster-id.txt") { $ClusterId = Get-Content "$dir\cluster-id.txt" -Raw }
    else { throw "ClusterId missing and no cluster-id.txt found." }
}

# Check for Region in file if not provided as parameter
if (-not $Region) {
    if (Test-Path "$dir\region.txt") { $Region = Get-Content "$dir\region.txt" -Raw }
    else { throw "Region missing and no region.txt found." }
}

# --- BEGIN AWS MODULE MANAGEMENT ---
Write-Host "Ensuring required AWS.Tools.SecretsManager module is installed and imported..."
$moduleName = 'AWS.Tools.SecretsManager'

# Check for monolithic modules (optional warning)
$monolithicModules = Get-Module -Name AWSPowerShell, AWSPowerShell.NetCore -ListAvailable
if ($monolithicModules) {
    Write-Warning "Monolithic AWS PowerShell modules detected. Consider using only modular AWS.Tools.* modules."
}

# Check if module is already loaded
if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
    Write-Host "$moduleName is already loaded." -ForegroundColor Green
} else {
    # Check if module is available (installed)
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Host "$moduleName not found. Installing..." -ForegroundColor Yellow
        # Installation should ideally happen in install-prerequisites.ps1
        try {
            Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers -Repository PSGallery -ErrorAction Stop
            Write-Host "$moduleName installed successfully." -ForegroundColor Green
        } catch {
            # Fix: Use $_ directly in the string
            Write-Error "Failed to install module ${moduleName}: $($_.Exception.Message)"
            if (-not (Get-Module -ListAvailable -Name $moduleName)) {
                throw "Installation failed and module $moduleName is still not available."
            } else {
                Write-Warning "Installation reported an error, but module $moduleName seems available now. Proceeding with import."
            }
        }
    } else {
        Write-Host "$moduleName is installed but not loaded."
    }
    # Import the module
    try {
        Write-Host "Importing $moduleName..."
        Import-Module $moduleName -ErrorAction Stop -DisableNameChecking
        Write-Host "$moduleName imported successfully." -ForegroundColor Green
    } catch {
        # Fix: Use $_ directly in the string
        Write-Error "Failed to import module ${moduleName}: $($_.Exception.Message)"
        throw "Failed to import required module $moduleName."
    }
}
# --- END AWS MODULE MANAGEMENT ---

Write-Host "Retrieving credentials"
$sec   = Get-SECSecretValue -SecretId "cloudhsm/$ClusterId/crypto-user" -Region $Region
$creds = $sec.SecretString | ConvertFrom-Json

# Validate credentials
# PSScriptAnalyzer disable PSUseDeclaredVarsMoreThanAssignments - justification: $creds is used in the following if statement
if (-not $creds -or -not $creds.username -or -not $creds.password) {
    throw "Invalid credentials format retrieved from Secrets Manager. Expected JSON with 'username' and 'password'."
}
# PSScriptAnalyzer enable PSUseDeclaredVarsMoreThanAssignments

# persist cluster-id
$ClusterId | Out-File "$dir\cluster-id.txt" -Encoding ascii

Write-Host "Building request.inf"
@"
[Version]
Signature="\`$Windows NT\$"

[NewRequest]
Subject = "CN=My Company Inc., O=My Company Inc., L=Seattle, S=Washington, C=US"
RequestType = PKCS10
HashAlgorithm = SHA256
KeyAlgorithm = RSA
KeyLength = 3072
ProviderName = "CloudHSM Key Storage Provider"
KeyUsage = "CERT_DIGITAL_SIGNATURE_KEY_USAGE"
MachineKeySet = True
Exportable = False

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.3 ; Code Signing
"@ | Out-File "$dir\request.inf" -Encoding ascii

Write-Host "Generating CSR"
certreq.exe -new "$dir\request.inf" "$dir\request.csr"
if (-not (Test-Path "$dir\request.csr")) { throw "CSR not created." }
Write-Host "CSR saved to $dir\request.csr"
