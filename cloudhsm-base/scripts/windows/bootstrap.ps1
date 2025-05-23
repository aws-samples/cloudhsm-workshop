param(
    [Parameter(Mandatory=$true)]
    [string]$ClusterId,

    [Parameter(Mandatory=$true)]
    [string]$BootstrapScriptUrl,

    [Parameter(Mandatory=$false)]
    [string]$Region = "eu-north-1",

    [Parameter(Mandatory=$false)]
    [string]$CustomerCaCertPath = "",

    [Parameter(Mandatory=$false)]
    [string]$ClusterCertPath = "",

    [Parameter(Mandatory=$false)]
    [hashtable]$ScriptsUrls = @{},

    [Parameter(Mandatory=$false)]
    [int]$MaxRetries = 3,

    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Set execution policy early to avoid permission issues
try {
    Write-Host "Setting execution policy to allow script execution..."
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope LocalMachine -Force
    Write-Host "Execution policy has been set to Bypass for process and Unrestricted for local machine"
} catch {
    Write-Host "Warning: Could not set execution policy. Script may fail if execution policy is restrictive."
    Write-Host "Error details: $_"
}

# Set TLS 1.2 for all HTTPS communications
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "Set TLS 1.2 for secure communications"
} catch {
    Write-Host "Warning: Could not set TLS 1.2. HTTPS downloads might fail."
}

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"  # Disable progress bars for faster downloads

# Start transcript logging
Start-Transcript -Path "C:\CloudHSM\bootstrap-transcript.log" -Append

Write-Host "Starting CloudHSM Windows bootstrap script"
Write-Host "ClusterId: $ClusterId"
Write-Host "Region: $Region"
Write-Host "BootstrapScriptUrl: $BootstrapScriptUrl"

# Create working directories
$workDir = "C:\CloudHSM"
if (-not (Test-Path $workDir)) {
    New-Item -Path $workDir -ItemType Directory -Force | Out-Null
    Write-Host "Created working directory: $workDir"
}

# Helper function to run scripts with retry
function Invoke-ScriptWithRetry {
    param(
        [string]$ScriptPath,
        [hashtable]$Parameters,
        [int]$MaxRetries = 3
    )

    $attempt = 0
    $success = $false

    while (-not $success -and $attempt -lt $MaxRetries) {
        $attempt++
        Write-Host "Executing $ScriptPath (Attempt $attempt of $MaxRetries)..."

        try {
            & $ScriptPath @Parameters
            $exitCode = $LASTEXITCODE

            if ($exitCode -eq $null -or $exitCode -eq 0) {
                Write-Host "Script executed successfully"
                $success = $true
            } else {
                throw "Script exited with code $exitCode"
            }
        } catch {
            Write-Host "Attempt $attempt failed: $_"

            if ($attempt -lt $MaxRetries) {
                $sleepTime = 5 * $attempt
                Write-Host "Retrying in $sleepTime seconds..."
                Start-Sleep -Seconds $sleepTime
            } else {
                Write-Host "All attempts failed. Moving on to next task."
                return $false
            }
        }
    }

    return $success
}

# Import utilities module if available
if (Test-Path "$workDir\CloudHSM-Utils.psm1") {
    try {
        Import-Module "$workDir\CloudHSM-Utils.psm1" -Force
        Write-Host "Imported CloudHSM-Utils module"
    } catch {
        Write-Host "Warning: Failed to import CloudHSM-Utils module: $_"
    }
}

# Download and install prerequisites
if (Test-Path "$workDir\install-prerequisites.ps1") {
    Write-Host "Running prerequisites installation script"
    $prereqParams = @{
        Region = $Region
        ClusterId = $ClusterId  # Add ClusterId parameter
    }
    if ($Force) { $prereqParams.Add("Force", $true) }

    Invoke-ScriptWithRetry -ScriptPath "$workDir\install-prerequisites.ps1" -Parameters $prereqParams -MaxRetries $MaxRetries
} else {
    Write-Host "Prerequisites script not found, skipping"
}

# Download and install dependencies
if (Test-Path "$workDir\install-dependencies.ps1") {
    Write-Host "Running dependencies installation script"
    $depParams = @{
        Region = $Region
        ClusterId = $ClusterId  # Add ClusterId parameter
    }
    if ($Force) { $depParams.Add("Force", $true) }

    Invoke-ScriptWithRetry -ScriptPath "$workDir\install-dependencies.ps1" -Parameters $depParams -MaxRetries $MaxRetries
} else {
    Write-Host "Dependencies script not found, skipping"
}

# Set up CloudHSM
if (Test-Path "$workDir\setup-cloudhsm.ps1") {
    Write-Host "Setting up CloudHSM integration"
    $setupParams = @{
        ClusterId = $ClusterId
        Region = $Region
    }

    if (-not [string]::IsNullOrEmpty($CustomerCaCertPath)) {
        $setupParams.Add("CustomerCaCertPath", $CustomerCaCertPath)
    }

    if (-not [string]::IsNullOrEmpty($ClusterCertPath)) {
        $setupParams.Add("ClusterCertPath", $ClusterCertPath)
    }

    if ($Force) { $setupParams.Add("Force", $true) }

    Invoke-ScriptWithRetry -ScriptPath "$workDir\setup-cloudhsm.ps1" -Parameters $setupParams -MaxRetries $MaxRetries
} else {
    Write-Host "CloudHSM setup script not found, skipping"
}

# Install signtool and related utilities - Remove Force parameter if not accepted
if (Test-Path "$workDir\install-signtool.ps1") {
    Write-Host "Installing code signing tools"
    # Check if install-signtool.ps1 supports Force parameter
    $signToolScriptContent = Get-Content "$workDir\install-signtool.ps1" -Raw
    $supportsForce = $signToolScriptContent -match "Force"

    $signParams = @{
        Region = $Region  # Add Region parameter explicitly
    }

    if ($Force -and $supportsForce) {
        $signParams.Add("Force", $true)
    }

    Invoke-ScriptWithRetry -ScriptPath "$workDir\install-signtool.ps1" -Parameters $signParams -MaxRetries $MaxRetries
} else {
    Write-Host "Signtool installation script not found, skipping"
}

# Create status file to indicate bootstrap completion
$statusFile = Join-Path $workDir "bootstrap-status.json"
$status = @{
    "ClusterId" = $ClusterId
    "Region" = $Region
    "Timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    "Status" = "Completed"
}
ConvertTo-Json $status | Out-File -FilePath $statusFile -Encoding utf8

Write-Host "Bootstrap process complete"
Stop-Transcript
exit 0
