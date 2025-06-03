<#
.SYNOPSIS
    Install prerequisites for CloudHSM code signing on Windows.
.DESCRIPTION
    Installs required Windows features, PowerShell modules, and other prerequisites
    needed for CloudHSM code signing on Windows.
.PARAMETER Region
    AWS region.
.PARAMETER Force
    Force installation even if prerequisites are already installed.
.PARAMETER ClusterId
    The CloudHSM cluster ID.
#>
param (
    [Parameter(Mandatory=$true)] [string]$ClusterId,
    [Parameter(Mandatory=$true)] [string]$Region,
    [Parameter(Mandatory=$false)] [switch]$Force
    )

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

$baseDir = "C:\CloudHSM"
$logFile = Join-Path $baseDir "logs\install-prerequisites.log"

# Create base directory if it doesn't exist
if (-not (Test-Path $baseDir)) {
    New-Item -Path $baseDir -ItemType Directory -Force | Out-Null
}

# Create log directory if it doesn't exist
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

# Start transcript
Start-Transcript -Path $logFile -Append

Write-Host "Installing prerequisites for CloudHSM code signing..."
Write-Host "ClusterId: $ClusterId"
Write-Host "Region: $Region"

# Ensure TLS 1.2 is used for PowerShellGet
Write-Host "Setting TLS 1.2 for PowerShellGet..."
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "TLS 1.2 set successfully."
} catch {
    Write-Warning "Failed to set TLS 1.2 explicitly: $($_.Exception.Message). Might not be required on newer systems."
}

# Ensure PSGallery is registered and trusted
Write-Host "Ensuring PSGallery repository is available and trusted..."
try {
    if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
        Write-Host "PSGallery repository not found. Registering..."
        Register-PSRepository -Default -InstallationPolicy Trusted -ErrorAction Stop
        Write-Host "PSGallery registered."
    } else {
        $repo = Get-PSRepository -Name PSGallery
        if ($repo.InstallationPolicy -ne 'Trusted') {
            Write-Host "PSGallery repository found but not trusted. Setting InstallationPolicy to Trusted..."
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction Stop
            Write-Host "PSGallery set to Trusted."
        } else {
            Write-Host "PSGallery is already registered and trusted."
        }
    }
} catch {
    Write-Error "Failed to configure PSGallery repository: $($_.Exception.Message)"
    throw
}

# Check if running as administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw "This script must be run as Administrator"
}

# Install required Windows features
Write-Host "Installing required Windows features..."
try {
    # Check if .NET Framework 3.5 is installed
    $netfx35 = Get-WindowsFeature -Name NET-Framework-Core -ErrorAction SilentlyContinue
    if ($netfx35 -and -not $netfx35.Installed) {
        Write-Host "Installing .NET Framework 3.5..."
        Install-WindowsFeature -Name NET-Framework-Core -ErrorAction Stop
    }

    # Check if PowerShell 5.1 is installed
    if ($PSVersionTable.PSVersion.Major -lt 5 -or ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -lt 1)) {
        Write-Host "PowerShell 5.1 or higher is required. Current version: $($PSVersionTable.PSVersion)"
        throw "Please update PowerShell to version 5.1 or higher and re-run the script."
    }

    # --- AWS Module Management ---
    Write-Host "Checking for existing AWS PowerShell module variants..."
    $monolithicModules = Get-Module -Name AWSPowerShell, AWSPowerShell.NetCore -ListAvailable
    if ($monolithicModules) {
        Write-Warning "Monolithic AWS PowerShell modules (AWSPowerShell or AWSPowerShell.NetCore) detected."
        Write-Warning "It is recommended to use the modular AWS.Tools.* modules instead."
        Write-Warning "Consider uninstalling monolithic modules to avoid potential conflicts: Uninstall-Module AWSPowerShell; Uninstall-Module AWSPowerShell.NetCore"
    }

    Write-Host "Ensuring required AWS.Tools modules are installed and imported..."
    $requiredModules = @(
        'AWS.Tools.Common',
        'AWS.Tools.SecretsManager',
        'AWS.Tools.SSM',
        'AWS.Tools.S3',
        'AWS.Tools.SimpleSystemsManagement'
        # Add other required AWS.Tools modules here if needed
    )

    foreach ($moduleName in $requiredModules) {
        Write-Host "Processing module: $moduleName"

        # Check if module is already loaded
        if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
            Write-Host "$moduleName is already loaded." -ForegroundColor Green
            continue # Skip to next module
        }

        # Check if module is available (installed)
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            Write-Host "$moduleName not found. Installing..."
            try {
                # Ensure NuGet is bootstrapped and PSGallery is trusted (already done earlier)
                Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers -Repository PSGallery -ErrorAction Stop
                 Write-Host "$moduleName installed successfully." -ForegroundColor Green
             } catch {
                # Use format operator to avoid potential parser issue with :$()
                Write-Error ("Failed to install module {0}: {1}" -f $moduleName, $_.Exception.Message)
                # Check if it became available despite the error (e.g., concurrency issue resolved)
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
            # Use format operator to avoid potential parser issue with :$()
            Write-Error ("Failed to import module {0}: {1}" -f $moduleName, $_.Exception.Message)
            throw "Failed to import required module $moduleName. Ensure it is correctly installed and there are no conflicts."
        }
    }
    # --- End AWS Module Management ---

    # Set AWS region (Requires AWS.Tools.Common)
    Write-Host "Setting default AWS region to $Region..."
    Set-DefaultAWSRegion -Region $Region
    Write-Host "Default AWS region set."

    Write-Host "AWS PowerShell modules checked/installed/imported successfully."

}
catch {
    Write-Error "Failed during prerequisite setup: $($_.Exception.Message)"
    throw
}

# Create status file
$status = @{
    "prerequisites_installed" = $true
    "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}
$status | ConvertTo-Json | Out-File -FilePath (Join-Path $baseDir "prerequisites-status.json") -Force

Write-Host "Prerequisites installation completed successfully."
Stop-Transcript
