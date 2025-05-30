<#
.SYNOPSIS
    Check status of CloudHSM code signing setup.
.DESCRIPTION
    Checks the status of the CloudHSM code signing setup and outputs a report.
.PARAMETER OutputPath
    Path to save the status report.
#>
param (
    [Parameter(Mandatory=$false)] [string]$OutputPath = "C:\CloudHSM\status-report.txt"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'
$VerbosePreference = 'Continue'

$baseDir = "C:\CloudHSM"

# Start transcript
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $baseDir "logs\status-check-$timestamp.log"
Start-Transcript -Path $logFile -Append

Write-Host "Checking CloudHSM code signing setup status..."

$report = @()
$report += "=== CloudHSM Code Signing Status Report ==="
$report += "Generated: $(Get-Date)"
$report += ""

# Check CloudHSM client installation
$report += "=== CloudHSM Client ==="
$clientInstalled = Test-Path "C:\Program Files\Amazon\CloudHSM\bin\configure.exe"
$report += "Client installed: $clientInstalled"

if ($clientInstalled) {
    # Check CloudHSM client service
    $service = Get-Service -Name AWSCloudHSMClient -ErrorAction SilentlyContinue
    if ($service) {
        $report += "Client service: $($service.Status)"
    } else {
        $report += "Client service: Not found"
    }
    
    # Check cluster configuration
    $clusterConfigPath = "C:\Program Files\Amazon\CloudHSM\data\cloudhsm_client.cfg"
    if (Test-Path $clusterConfigPath) {
        $report += "Cluster configuration: Present"
        try {
            $clusterConfig = Get-Content $clusterConfigPath -Raw | ConvertFrom-Json
            $report += "  Server: $($clusterConfig.server.server)"
        } catch {
            $report += "  Could not parse cluster configuration"
        }
    } else {
        $report += "Cluster configuration: Not found"
    }
}

# Check SignTool installation
$report += ""
$report += "=== SignTool ==="
$signToolPath = Join-Path $baseDir "signing-tools\signtool.exe"
$signToolInstalled = Test-Path $signToolPath
$report += "SignTool installed: $signToolInstalled"

if ($signToolInstalled) {
    try {
        $signToolVersion = & $signToolPath /? 2>&1
        $report += "SignTool version: $($signToolVersion[0])"
    } catch {
        $report += "Could not determine SignTool version"
    }
}

# Check certificates
$report += ""
$report += "=== Certificates ==="
# Initialize as empty array
$certs = @()
try {
    # Filter by KSP for reliability and always wrap result in @() to ensure it's an array
    $allCerts = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop
    if ($null -ne $allCerts) {
        $filteredCerts = @($allCerts | Where-Object { 
            try {
                # Safely access properties with null checks
                $_.HasPrivateKey -and 
                ($null -ne $_.PrivateKey) -and 
                ($null -ne $_.PrivateKey.CspKeyContainerInfo) -and
                ($_.PrivateKey.CspKeyContainerInfo.ProviderName -eq "CloudHSM Key Storage Provider")
            } catch {
                # If any error occurs during property access, skip this cert
                Write-Verbose "Skipping certificate due to error accessing properties: $($_.Thumbprint)"
                $false
            }
        })
        
        # Ensure we have an array even if filtering returned just one item or null
        if ($null -ne $filteredCerts) {
            $certs = @($filteredCerts)
        }
    }
} catch {
    $report += "Error accessing certificate store: $($_.Exception.Message)"
}

# Get count safely - use array Length property
$certCount = if ($null -eq $certs) { 0 } else { $certs.Length }

$report += "CloudHSM KSP code signing certificates: $certCount"

if ($certCount -gt 0) {
    foreach ($cert in $certs) {
        $report += "  Subject: $($cert.Subject)"
        $report += "  Thumbprint: $($cert.Thumbprint)"
        $report += "  Valid from: $($cert.NotBefore) to $($cert.NotAfter)"
        $report += "  Issuer: $($cert.Issuer)"
        $report += ""
    }
}

# Check for CSR
$csrPath = Join-Path $baseDir "request.csr"
$csrExists = Test-Path $csrPath
$report += ""
$report += "=== CSR ==="
$report += "CSR file exists ($csrPath): $csrExists"

# Output report
$report | Out-File -FilePath $OutputPath -Force
Write-Host "Status report saved to: $OutputPath"

# Display report
$report | ForEach-Object { Write-Host $_ }

Stop-Transcript
