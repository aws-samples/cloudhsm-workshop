<#
.SYNOPSIS
    Install dependencies for CloudHSM code signing on Windows.
.DESCRIPTION
    Installs required dependencies for CloudHSM code signing on Windows,
    including the Windows SDK and other necessary components.
.PARAMETER ClusterId
    The CloudHSM cluster ID.
.PARAMETER Region
    AWS region.
.PARAMETER Force
    Force installation even if dependencies are already installed.
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
$logFile = Join-Path $baseDir "logs\install-dependencies.log"

# Create log directory if it doesn't exist
if (-not (Test-Path (Split-Path $logFile))) {
    New-Item -Path (Split-Path $logFile) -ItemType Directory -Force | Out-Null
}

# Start transcript
Start-Transcript -Path $logFile -Append

Write-Host "Installing dependencies for CloudHSM code signing..."
Write-Host "ClusterId: $ClusterId"
Write-Host "Region: $Region"

# Install Windows SDK components
try {
    Write-Host "Installing Windows SDK components..."
    
    # Check if Chocolatey is installed
    if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
        Write-Host "Chocolatey not found. Installing Chocolatey..."
        Set-ExecutionPolicy Bypass -Scope Process -Force
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
        
        # First, clean up any existing failed/partial installation
        if (Test-Path "C:\ProgramData\chocolatey") {
            Write-Host "Found existing Chocolatey directory. Cleaning up first..."
            Remove-Item -Path "C:\ProgramData\chocolatey" -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        # Install Chocolatey using the official script
        try {
            Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
        } 
        catch {
            Write-Warning "Error during Chocolatey installation: ${_}"
            
            # Alternative manual Chocolatey installation
            Write-Host "Attempting alternative Chocolatey installation..."
            $env:chocolateyVersion = '1.2.0'
            $tempDir = [System.IO.Path]::GetTempPath()
            $chocoInstallPS1 = Join-Path $tempDir "chocoInstall.ps1"
            $installUrl = 'https://community.chocolatey.org/install.ps1'
            
            # Download the script
            (New-Object System.Net.WebClient).DownloadFile($installUrl, $chocoInstallPS1)
            
            # Execute the script
            & $chocoInstallPS1
            
            # Check if installation was successful
            if (-not (Test-Path "C:\ProgramData\chocolatey\bin\choco.exe")) {
                throw "Failed to install Chocolatey using alternative method"
            }
        }
        
        # Refresh environment variables to include Chocolatey
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        # Verify Chocolatey is accessible
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            Write-Host "Adding Chocolatey to PATH manually..."
            $env:Path += ";C:\ProgramData\chocolatey\bin"
        }
        
        if (-not (Get-Command choco -ErrorAction SilentlyContinue)) {
            throw "Chocolatey installation appears successful but 'choco' command is not available"
        }
    }

    # Install AWS CLI
    Write-Host "Installing AWS CLI..."
    & choco install awscli -y --force --ignore-checksums
    
    # Install Windows SDK
    Write-Host "Installing Windows SDK (using windows-sdk-10.1 package)..."
    # Use --force to ensure installation even if there's a problem with previous installation
    # Allow empty checksums as SDK installers sometimes have issues
    & choco install windows-sdk-10.1 -y --force --allow-empty-checksums --ignore-checksums
    
    # Install Visual Studio Build Tools (Using 2022 as per README)
    Write-Host "Installing Visual Studio 2022 Build Tools..."
    & choco install visualstudio2022buildtools -y --force --ignore-checksums
    
    # Install .NET Framework 4.8 Developer Pack
    Write-Host "Installing .NET Framework 4.8 Developer Pack..."
    & choco install netfx-4.8-devpack -y --force --ignore-checksums
}
catch {
    Write-Error ("Failed to install dependencies: {0}" -f $_.Exception.Message)
    throw
}

# --- AWS Module Management ---

Write-Host "Ensuring required AWS.Tools.SecretsManager module is installed and imported..."
$moduleName = 'AWS.Tools.SecretsManager'
# Check if module is already loaded
if (Get-Module -Name $moduleName -ErrorAction SilentlyContinue) {
    Write-Host "$moduleName is already loaded." -ForegroundColor Green
} else {
    # Check if module is available (installed)
    if (-not (Get-Module -ListAvailable -Name $moduleName)) {
        Write-Host "$moduleName not found. Installing..." -ForegroundColor Yellow
        try {
            Install-Module -Name $moduleName -Force -AllowClobber -Scope AllUsers -Repository PSGallery -ErrorAction Stop
            Write-Host "$moduleName installed successfully." -ForegroundColor Green
        } catch {
            Write-Error ("Failed to install module {0}: {1}" -f $moduleName, $_.Exception.Message)
            throw "Installation failed and module $moduleName is still not available."
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
        Write-Error ("Failed to import module {0}: {1}" -f $moduleName, $_.Exception.Message)
        throw "Failed to import required module $moduleName."
    }
}


Stop-Transcript
