<#
.SYNOPSIS
    Install SignTool for CloudHSM code signing on Windows.
.DESCRIPTION
    Copies SignTool and its dependencies from the Windows SDK for CloudHSM code signing on Windows.
.PARAMETER Region
    AWS region.
.PARAMETER Force
    Force installation even if SignTool is already installed.
#>
param (
    [Parameter(Mandatory=$false)] [string]$Region = $env:AWS_REGION,
    [Parameter(Mandatory=$false)] [switch]$Force
)

# If Region is still null or empty after trying environment variable, prompt for it
if ([string]::IsNullOrEmpty($Region)) {
    $Region = Read-Host -Prompt 'AWS Region not set. Please enter AWS Region'
    if ([string]::IsNullOrEmpty($Region)) {
        throw 'Region not set: cannot continue without AWS Region.'
    }
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

$baseDir = "C:\CloudHSM"
$logsDir = Join-Path $baseDir "logs"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logsDir "install-signtool-$timestamp.log"

# Create log directory if it doesn't exist
if (-not (Test-Path $logsDir)) {
    New-Item -Path $logsDir -ItemType Directory -Force | Out-Null
}

# Start transcript
Start-Transcript -Path $logFile -Append

Write-Host "Installing SignTool for CloudHSM code signing..." -ForegroundColor Cyan
Write-Host "Region: $Region" -ForegroundColor Cyan
if ($Force) {
    Write-Host "Force mode enabled - will reinstall even if already present" -ForegroundColor Yellow
}

# Set AWS region
try {
    Write-Host "Setting AWS region to $Region..." -ForegroundColor Cyan
    Set-DefaultAWSRegion -Region $Region -ErrorAction Stop
    Write-Host "AWS region set successfully." -ForegroundColor Green
} catch {
    Write-Warning "Failed to set AWS region: $($_.Exception.Message)"
    # Continue execution as this is not critical
}

# Create signing tools directory
$signingToolsDir = Join-Path $baseDir "signing-tools"
if (-not (Test-Path $signingToolsDir)) {
    Write-Host "Creating signing tools directory: $signingToolsDir" -ForegroundColor Cyan
    New-Item -Path $signingToolsDir -ItemType Directory -Force | Out-Null
}

# Add SHA256 hash verification for security
function Verify-FileHash {
    param (
        [Parameter(Mandatory=$true)] [string]$FilePath,
        [Parameter(Mandatory=$false)] [string]$ExpectedHash
    )

    try {
        if (-not (Test-Path $FilePath)) {
            Write-Host "File does not exist: $FilePath" -ForegroundColor Red
            return $false
        }

        $hash = Get-FileHash -Path $FilePath -Algorithm SHA256 -ErrorAction Stop

        if ([string]::IsNullOrEmpty($ExpectedHash)) {
            # Just log the hash if we don't have an expected value
            Write-Host "File: $FilePath, SHA256: $($hash.Hash)" -ForegroundColor Cyan
            return $true
        } else {
            if ($hash.Hash -eq $ExpectedHash) {
                Write-Host "Hash verification successful for: $FilePath" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Hash verification failed for: $FilePath" -ForegroundColor Red
                Write-Host "Expected: $ExpectedHash" -ForegroundColor Red
                Write-Host "Actual: $($hash.Hash)" -ForegroundColor Red
                return $false
            }
        }
    } catch {
        Write-Host "Failed to verify file hash: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Skip if tools already exist and Force is not set
$signToolPath = Join-Path $signingToolsDir "signtool.exe"
if ((Test-Path $signToolPath) -and (-not $Force)) {
    Write-Host "SignTool already installed at $signToolPath and Force not specified. Skipping installation." -ForegroundColor Green
    Stop-Transcript
    return
}

# Copy SignTool and dependencies from Windows SDK
try {
    Write-Host "Copying SignTool and dependencies from Windows SDK..." -ForegroundColor Cyan

    $requiredFiles = @("signtool.exe", "wintrust.dll", "crypt32.dll", "mssign32.dll")
    $foundFiles = @()
    $toolsFound = $false

    # Check for Windows SDK installations
    $sdkPaths = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x86",
        "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x64",
        "${env:ProgramFiles(x86)}\Windows Kits\8.1\bin\x86"
    )

    $signToolPathFound = $null
    foreach ($sdkPath in $sdkPaths) {
        try {
            $possiblePaths = Get-Item -Path $sdkPath -ErrorAction SilentlyContinue
            if ($possiblePaths) {
                foreach ($path in $possiblePaths) {
                    $testPath = Join-Path $path.FullName "signtool.exe"
                    if (Test-Path $testPath) {
                        $signToolPathFound = $testPath
                        Write-Host "Found SignTool at: $signToolPathFound" -ForegroundColor Green
                        break
                    }
                }
            }
        } catch {
            Write-Host "Error checking SDK path ${sdkPath}: $($_.Exception.Message)" -ForegroundColor Yellow
        }
        if ($signToolPathFound) { break }
    }

    if ($signToolPathFound) {
        # Copy signtool.exe and its dependencies
        $sourcePath = Split-Path $signToolPathFound -Parent

        foreach ($file in $requiredFiles) {
            $sourceFile = Join-Path $sourcePath $file
            $destFile = Join-Path $signingToolsDir $file

            if (Test-Path $sourceFile) {
                Write-Host "Copying $file from Windows SDK..." -ForegroundColor Cyan
                Copy-Item -Path $sourceFile -Destination $destFile -Force

                if (Test-Path $destFile) {
                    Verify-FileHash -FilePath $destFile
                    $foundFiles += $file
                }
            } else {
                Write-Host "$file not found in Windows SDK, checking system32..." -ForegroundColor Yellow
                # Try to copy from system32
                $systemFile = Join-Path $env:SystemRoot "System32\$file"
                if (Test-Path $systemFile) {
                    Write-Host "Copying $file from System32..." -ForegroundColor Cyan
                    Copy-Item -Path $systemFile -Destination $destFile -Force

                    if (Test-Path $destFile) {
                        Verify-FileHash -FilePath $destFile
                        $foundFiles += $file
                    }
                } else {
                    Write-Warning "$file not found in Windows SDK or System32"
                }
            }
        }

        # Check if we found all required files
        $missingRequiredSDK = @($requiredFiles | Where-Object { $_ -notin $foundFiles })
        if ($missingRequiredSDK.Length -eq 0) {
            $toolsFound = $true
            Write-Host "Successfully copied all required signing tools from Windows SDK/System32" -ForegroundColor Green
        } else {
            Write-Host "Missing the following required files from Windows SDK/System32: $($missingRequiredSDK -join ', ')" -ForegroundColor Yellow
        }
    }

    # Verify SignTool was copied
    $signToolPath = Join-Path $signingToolsDir "signtool.exe"
    if (-not (Test-Path $signToolPath)) {
        throw "SignTool not found after installation attempt. Please ensure Windows SDK is installed on this system."
    }

    # Verify dependencies are present
    $missingDependencies = @()
    foreach ($dependency in $requiredFiles | Where-Object { $_ -ne "signtool.exe" }) {
        if (-not (Test-Path (Join-Path $signingToolsDir $dependency))) {
            $missingDependencies += $dependency
        }
    }

    if ($missingDependencies.Length -gt 0) {
        Write-Warning "The following dependencies are missing: $($missingDependencies -join ', '). Code signing may not work properly."
    }

    # Test signtool execution
    try {
        Write-Host "Testing SignTool execution..." -ForegroundColor Cyan
        $env:PATH = "$signingToolsDir;$env:PATH"
        $signToolOutput = & $signToolPath /? 2>&1

        if ($LASTEXITCODE -eq 0) {
            Write-Host "SignTool test execution successful!" -ForegroundColor Green
            Write-Host "SignTool version: $($signToolOutput[0])" -ForegroundColor Green
        } else {
            Write-Warning "SignTool test execution returned exit code $LASTEXITCODE"
            Write-Warning "Output: $signToolOutput"
        }
    } catch {
        Write-Warning "Failed to execute SignTool: $($_.Exception.Message)"
    }

    # Create README file with instructions
    $readmePath = Join-Path $signingToolsDir "README.txt"
    @"
SignTool and Dependencies for CloudHSM Code Signing
==================================================

Files in this directory:
- signtool.exe: Microsoft's tool for signing files
- wintrust.dll: Required dependency for SignTool
- crypt32.dll: Required dependency for SignTool
- mssign32.dll: Required dependency for SignTool

To use SignTool with CloudHSM, make sure:
1. The CloudHSM client is properly configured and running
2. A code signing certificate with a private key in the CloudHSM is installed in the certificate store
3. The certificate has a friendly name assigned for easy reference

Example usage:
.\signtool.exe sign /v /fd SHA256 /n "Your Certificate Subject" /tr http://timestamp.digicert.com /td SHA256 <file_to_sign>

For help with SignTool, run:
.\signtool.exe /?
"@ | Out-File -FilePath $readmePath -Force

    # Create status file
    $status = @{
        "signtool_installed" = $true
        "signtool_path" = $signToolPath
        "dependencies_found" = ($missingDependencies.Length -eq 0)
        "missing_dependencies" = $missingDependencies
        "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $statusPath = Join-Path $baseDir "signtool-status.json"
    $status | ConvertTo-Json | Out-File -FilePath $statusPath -Force
    Write-Host "SignTool status saved to: $statusPath" -ForegroundColor Cyan

    Write-Host "SignTool installed successfully at: $signToolPath" -ForegroundColor Green
} catch {
    Write-Host "Failed to install SignTool: $($_.Exception.Message)" -ForegroundColor Red
    throw
}

Stop-Transcript
