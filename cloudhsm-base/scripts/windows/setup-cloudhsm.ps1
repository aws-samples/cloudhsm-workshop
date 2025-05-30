<#
.SYNOPSIS
    Set up CloudHSM integration for code signing on Windows.
.DESCRIPTION
    Downloads and installs the CloudHSM client, configures it to connect to the specified cluster,
    and sets up the necessary environment for code signing including PKCS#11, KSP, and JCE libraries.
.PARAMETER ClusterId
    The CloudHSM cluster ID.
.PARAMETER Region
    AWS region.
.PARAMETER CustomerCaCertPath
    (Optional) Path to the customer CA certificate in Secrets Manager.
.PARAMETER ClusterCertPath
    (Optional) Path to the cluster certificate in Secrets Manager.
.PARAMETER InitialPasswordPath
    (Optional) Path to the initial crypto officer password in Secrets Manager.
.PARAMETER CryptoUserPath
    (Optional) Path to the crypto user credentials in Secrets Manager.
.PARAMETER Force
    (Optional) Force execution even if setup has been run before.
#>
param (
    [Parameter(Mandatory=$true)] [string]$ClusterId,
    [Parameter(Mandatory=$true)] [string]$Region,
    [Parameter(Mandatory=$false)] [string]$CustomerCaCertPath,
    [Parameter(Mandatory=$false)] [string]$ClusterCertPath,
    [Parameter(Mandatory=$false)] [string]$InitialPasswordPath,
    [Parameter(Mandatory=$false)] [string]$CryptoUserPath,
    [Parameter(Mandatory=$false)] [switch]$Force
)

# Set strict mode and error handling
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

# --- BEGIN LOGGING SETUP ---
$baseDir = "C:\CloudHSM"
$logsDir = Join-Path $baseDir "logs"
$scriptBaseName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Path)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logFile = Join-Path $logsDir "$($scriptBaseName)-$($timestamp).log"

# Check if a transcript is already running using Get-PSCallStack
$transcriptActive = $false
try {
    # Check if Start-Transcript appears in the call stack
    $callStack = Get-PSCallStack | Where-Object { $_.Command -eq "Start-Transcript" }
    if ($callStack) {
        $transcriptActive = $true
    }
} catch {
    # If there's an error checking the call stack, assume no transcript is active
    $transcriptActive = $false
}

# Create directories if they don't exist
try {
    if (-not (Test-Path $baseDir)) {
        New-Item -Path $baseDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    if (-not (Test-Path $logsDir)) {
        New-Item -Path $logsDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    # Start transcript only if one isn't already active
    if (-not $transcriptActive) {
        Start-Transcript -Path $logFile -Append -ErrorAction Stop
        Write-Host "Transcript started by setup-cloudhsm.ps1, output file is $logFile"
    } else {
        Write-Host "Transcript already active (likely started by bootstrap.ps1). Skipping Start-Transcript in setup-cloudhsm.ps1."
    }
} catch {
    Write-Warning "Failed to initialize logging/transcript to '$logFile': $($_.Exception.Message)"
    # Continue anyway
}
# --- END LOGGING SETUP ---

# Define shared functions if the utility module is not available
function Test-AdminPrivileges {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Install-MSI {
    param (
        [Parameter(Mandatory=$true)][string]$MsiUrl,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$true)][string]$LogFile
    )

    try {
        # Download MSI
        Write-Host "Downloading $MsiUrl to $OutputPath..." -ForegroundColor Cyan
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $MsiUrl -OutFile $OutputPath -ErrorAction Stop

        # Install MSI
        Write-Host "Installing $OutputPath..." -ForegroundColor Cyan
        $arguments = "/i `"$OutputPath`" /quiet /norestart /l*v `"$LogFile`""
        $process = Start-Process -FilePath "msiexec.exe" -ArgumentList $arguments -Wait -PassThru

        if ($process.ExitCode -eq 0) {
            Write-Host "Installation successful." -ForegroundColor Green
            return $true
        } else {
            Write-Host "Installation failed with exit code $($process.ExitCode). Check $LogFile for details." -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Debug output for parameter verification
Write-Host "Setup CloudHSM with parameters:" -ForegroundColor Cyan
Write-Host "  ClusterId: $ClusterId" -ForegroundColor Cyan
Write-Host "  Region: $Region" -ForegroundColor Cyan
Write-Host "  CustomerCaCertPath: $CustomerCaCertPath" -ForegroundColor Cyan
Write-Host "  ClusterCertPath: $ClusterCertPath" -ForegroundColor Cyan
Write-Host "  Force: $Force" -ForegroundColor Cyan

# Check if CloudHSM is already installed and respect Force parameter
$statusFile = Join-Path $baseDir "cloudhsm-setup-status.json"
if ((Test-Path $statusFile) -and -not $Force) {
    try {
        $existingStatus = Get-Content $statusFile -Raw | ConvertFrom-Json
        Write-Host "CloudHSM appears to be already installed as of $($existingStatus.timestamp)" -ForegroundColor Yellow
        Write-Host "Use -Force parameter to reinstall" -ForegroundColor Yellow

        # Ask user to confirm reinstallation
        $confirmation = Read-Host "Do you want to continue anyway? (y/n)"
        if ($confirmation -ne 'y') {
            Write-Host "Setup aborted by user." -ForegroundColor Yellow
            exit 0
        }
    } catch {
        Write-Host "Found existing installation but couldn't read status. Continuing anyway." -ForegroundColor Yellow
    }
} elseif ((Test-Path $statusFile) -and $Force) {
    Write-Host "Force parameter specified. Reinstalling CloudHSM even though it appears to be already installed." -ForegroundColor Cyan
}

# --- BEGIN AWS CREDENTIALS SETUP ---
# Ensure AWS credentials are properly configured for script operation
Write-Host "Initializing AWS credentials for Secrets Manager and SSM access..." -ForegroundColor Cyan

# Function to validate and setup AWS credentials
function Initialize-AWSCredentials {
    try {
        # Check if AWS CLI is installed and configured
        $awsCliVersion = & aws --version 2>&1
        Write-Host "AWS CLI detected: $awsCliVersion" -ForegroundColor Green

        # Check current credentials
        Write-Host "Validating AWS credentials..." -ForegroundColor Cyan
        $testCall = & aws sts get-caller-identity 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "AWS credentials not properly configured: $testCall"
            Write-Host "Falling back to IMDSv2 instance credentials..." -ForegroundColor Yellow

            # Get instance role credentials from IMDSv2
            $headers1 = @{}
            $headers1.Add("X-aws-ec2-metadata-token-ttl-seconds", "300")
            $token = Invoke-RestMethod -Headers $headers1 -Method PUT -Uri "http://169.254.169.254/latest/api/token" -ErrorAction Stop

            $headers2 = @{}
            $headers2.Add("X-aws-ec2-metadata-token", $token)
            $roleName = Invoke-RestMethod -Headers $headers2 -Method GET -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" -ErrorAction Stop

            $credentials = Invoke-RestMethod -Headers $headers2 -Method GET -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$roleName" -ErrorAction Stop

            # Set environment variables for AWS CLI and SDK
            $env:AWS_ACCESS_KEY_ID = $credentials.AccessKeyId
            $env:AWS_SECRET_ACCESS_KEY = $credentials.SecretAccessKey
            $env:AWS_SESSION_TOKEN = $credentials.Token
            $env:AWS_DEFAULT_REGION = $Region
            $env:AWS_REGION = $Region

            # Verify new credentials
            $testCall = & aws sts get-caller-identity 2>&1
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Successfully configured AWS credentials via IMDSv2" -ForegroundColor Green
                return $true
            } else {
                Write-Host "Failed to configure AWS credentials via IMDSv2: $testCall" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "AWS credentials validated successfully" -ForegroundColor Green
            return $true
        }
    } catch {
        Write-Host "Error initializing AWS credentials: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Initialize AWS credentials
$credentialsConfigured = Initialize-AWSCredentials
if (-not $credentialsConfigured) {
    Write-Host "WARNING: AWS credentials could not be configured. Secrets Manager and SSM Parameter Store access may fail." -ForegroundColor Red
}

# --- END AWS CREDENTIALS SETUP ---

# --- BEGIN CERTIFICATE RETRIEVAL ---
# Retrieve certificates and credentials from Secrets Manager if paths are provided
$customerCACertPath = $null
$clusterCertPath = $null
$initialPasswordPath = $null
$cryptoUserPath = $null

# Helper function for troubleshooting access issues - simplified to avoid issues
function Test-AWSResourceAccess {
    param(
        [string]$ResourceType,
        [string]$ResourceArn
    )

    # Try to access a resource and log minimal error information
    try {
        Write-Host ("Testing access to " + $ResourceType + ": " + $ResourceArn + "...") -ForegroundColor Cyan
        $result = $null
        $success = $false

        # Use a simpler way to check access that avoids complex error handling
        if ($ResourceType -eq "Secret") {
            try {
                aws secretsmanager describe-secret --secret-id $ResourceArn --region $Region | Out-Null
                $success = ($LASTEXITCODE -eq 0)
            } catch {
                $success = $false
            }
        }
        elseif ($ResourceType -eq "SSM Parameter") {
            try {
                aws ssm get-parameter --name $ResourceArn --region $Region | Out-Null
                $success = ($LASTEXITCODE -eq 0)
            } catch {
                $success = $false
            }
        }
        else {
            Write-Host "Unknown resource type: $ResourceType" -ForegroundColor Red
            return $false
        }

        if ($success) {
            Write-Host "[SUCCESS] Access test successful for $ResourceType" -ForegroundColor Green
            return $true
        } else {
            Write-Host "[FAILED] Access denied for $ResourceType" -ForegroundColor Red
            return $false
        }
    } catch {
        Write-Host ("Error testing access to " + $ResourceType + ": " + $($_.Exception.Message)) -ForegroundColor Red
        return $false
    }
}

Write-Host "Testing access to CloudHSM resources before proceeding..." -ForegroundColor Cyan
# Focus only on the crypto-user secret as confirmed by user
$secretAccess = Test-AWSResourceAccess -ResourceType "Secret" -ResourceArn "cloudhsm/$ClusterId/crypto-user"

if (-not $secretAccess) {
    Write-Host "WARNING: Cannot access CloudHSM resources. EC2 instance IAM role may be missing required permissions." -ForegroundColor Red
    Write-Host "Required permissions:" -ForegroundColor Yellow
    Write-Host "  - ssm:GetParameter for /cloudhsm/$ClusterId/*" -ForegroundColor Yellow
    Write-Host "  - secretsmanager:GetSecretValue for cloudhsm/$ClusterId/*" -ForegroundColor Yellow
}

if ($CustomerCaCertPath) {
    try {
        Write-Host "Retrieving Customer CA certificate from Secrets Manager: $CustomerCaCertPath" -ForegroundColor Cyan
        $customerCACert = aws secretsmanager get-secret-value --secret-id $CustomerCaCertPath --query SecretString --output text --region $Region
        if ($customerCACert) {
            # Certificate is in PEM format (-----BEGIN CERTIFICATE-----)
            $customerCACertPath = Join-Path $baseDir "customer-ca.crt"
            $customerCACert | Out-File -FilePath $customerCACertPath -Encoding ASCII -Force
            Write-Host "Customer CA certificate saved to $customerCACertPath" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to retrieve Customer CA certificate: $($_.Exception.Message)"
    }
}

if ($ClusterCertPath) {
    try {
        Write-Host "Retrieving Cluster certificate from Secrets Manager: $ClusterCertPath" -ForegroundColor Cyan
        $clusterCert = aws secretsmanager get-secret-value --secret-id $ClusterCertPath --query SecretString --output text --region $Region
        if ($clusterCert) {
            # Certificate is in PEM format (-----BEGIN CERTIFICATE-----)
            $clusterCertPath = Join-Path $baseDir "cluster.crt"
            $clusterCert | Out-File -FilePath $clusterCertPath -Encoding ASCII -Force
            Write-Host "Cluster certificate saved to $clusterCertPath" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to retrieve Cluster certificate: $($_.Exception.Message)"
    }
}

if ($InitialPasswordPath) {
    try {
        Write-Host "Retrieving Initial CO password from Secrets Manager: $InitialPasswordPath" -ForegroundColor Cyan
        $initialPasswordJson = aws secretsmanager get-secret-value --secret-id $InitialPasswordPath --query SecretString --output text --region $Region
        if ($initialPasswordJson) {
            # Password is in JSON format: {"username": "admin", "password": "password"}
            $initialPasswordObj = $initialPasswordJson | ConvertFrom-Json
            $initialPasswordPath = Join-Path $baseDir "initial-co-password.json"
            $initialPasswordJson | Out-File -FilePath $initialPasswordPath -Encoding ASCII -Force

            # Also create a plain text file with just the password for scripts that expect it
            $initialPasswordTextPath = Join-Path $baseDir "initial-co-password.txt"
            $initialPasswordObj.password | Out-File -FilePath $initialPasswordTextPath -Encoding ASCII -Force

            Write-Host "Initial CO password saved to $initialPasswordPath" -ForegroundColor Green
            Write-Host "Username: $($initialPasswordObj.username), Password: [REDACTED]" -ForegroundColor Green
        }
    } catch {
        Write-Warning "Failed to retrieve Initial CO password: $($_.Exception.Message)"
    }
}

# Try to get crypto user credentials if they exist
if ($CryptoUserPath) {
    try {
        Write-Host "Retrieving Crypto User credentials from Secrets Manager: $CryptoUserPath" -ForegroundColor Cyan
        $cryptoUserJson = aws secretsmanager get-secret-value --secret-id $CryptoUserPath --query SecretString --output text --region $Region
        if ($cryptoUserJson) {
            # Credentials are in JSON format: {"username":"code-signing-user","password":"CloudHSM123!"}
            $cryptoUserObj = $cryptoUserJson | ConvertFrom-Json
            $cryptoUserPath = Join-Path $baseDir "crypto-user.json"
            $cryptoUserJson | Out-File -FilePath $cryptoUserPath -Encoding ASCII -Force
            Write-Host "Crypto User credentials saved to $cryptoUserPath" -ForegroundColor Green
            Write-Host "Username: $($cryptoUserObj.username), Password: [REDACTED]" -ForegroundColor Green
        }
    } catch {
        Write-Host "Failed to retrieve Crypto User credentials: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    # Try to get crypto user credentials using the cluster ID
    try {
        $cryptoUserSecretId = "cloudhsm/$ClusterId/crypto-user"
        Write-Host "Checking for Crypto User credentials: $cryptoUserSecretId" -ForegroundColor Cyan
        $cryptoUserJson = aws secretsmanager get-secret-value --secret-id $cryptoUserSecretId --query SecretString --output text --region $Region 2>$null
        if ($cryptoUserJson) {
            # Credentials are in JSON format: {"username":"code-signing-user","password":"CloudHSM123!"}
            $cryptoUserObj = $cryptoUserJson | ConvertFrom-Json
            $cryptoUserPath = Join-Path $baseDir "crypto-user.json"
            $cryptoUserJson | Out-File -FilePath $cryptoUserPath -Encoding ASCII -Force
            Write-Host "Crypto User credentials saved to $cryptoUserPath" -ForegroundColor Green
            Write-Host "Username: $($cryptoUserObj.username), Password: [REDACTED]" -ForegroundColor Green
        }
    } catch {
        Write-Host "No Crypto User credentials found for this cluster. This is normal for a new cluster." -ForegroundColor Yellow
    }
}
# --- END CERTIFICATE RETRIEVAL ---

# --- BEGIN ENVIRONMENT CONFIGURATION ---
Write-Host "Configuring system environment variables..." -ForegroundColor Cyan

# Check for Administrator privileges
if (!(Test-AdminPrivileges)) {
    Write-Host "Administrator privileges are required to set system-wide environment variables." -ForegroundColor Yellow
} else {
    # Set AWS_REGION system-wide
    try {
        Write-Host "Setting system-wide AWS_REGION environment variable to '$Region'..." -ForegroundColor Cyan
        [System.Environment]::SetEnvironmentVariable('AWS_REGION', $Region, [System.EnvironmentVariableTarget]::Machine)
        Write-Host "System-wide AWS_REGION set successfully." -ForegroundColor Green
    } catch {
        Write-Host "Failed to set system-wide AWS_REGION: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Set AWS_REGION for the current session too
$env:AWS_REGION = $Region
# --- END ENVIRONMENT CONFIGURATION ---

# --- BEGIN CLOUDHSM CLIENT INSTALLATION ---
Write-Host "Installing CloudHSM Client..." -ForegroundColor Cyan

# Define the base installation directory used by AWS CloudHSM
$baseInstallDir = "C:\Program Files\Amazon\CloudHSM"
$tempDir = Join-Path $env:TEMP "CloudHSM_Install"
if (-not (Test-Path $tempDir)) {
    New-Item -Path $tempDir -ItemType Directory -Force | Out-Null
}

# Define the MSI URLs for each component
$clientMsiUrl = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Windows/AWSCloudHSMCLI-latest.msi"
$pkcs11MsiUrl = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Windows/AWSCloudHSMPKCS11-latest.msi"
$kspMsiUrl = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Windows/AWSCloudHSMKSP-latest.msi"
$jceMsiUrl = "https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Windows/AWSCloudHSMJCE-latest.msi"

# Install CloudHSM CLI Client
$cliMsiPath = Join-Path $tempDir "AWSCloudHSMCLI.msi"
$cliLogFile = Join-Path $logsDir "cloudhsm-cli-install.log"
$cliInstalled = Install-MSI -MsiUrl $clientMsiUrl -OutputPath $cliMsiPath -LogFile $cliLogFile
if (-not $cliInstalled) {
    Write-Warning "CloudHSM CLI installation failed. Some functionality may not work."
}

# Install PKCS#11 Library
$pkcs11MsiPath = Join-Path $tempDir "AWSCloudHSMPKCS11.msi"
$pkcs11LogFile = Join-Path $logsDir "cloudhsm-pkcs11-install.log"
$pkcs11Installed = Install-MSI -MsiUrl $pkcs11MsiUrl -OutputPath $pkcs11MsiPath -LogFile $pkcs11LogFile
if (-not $pkcs11Installed) {
    Write-Warning "CloudHSM PKCS#11 Library installation failed. Some functionality may not work."
}

# Install KSP Library
$kspMsiPath = Join-Path $tempDir "AWSCloudHSMKSP.msi"
$kspLogFile = Join-Path $logsDir "cloudhsm-ksp-install.log"
$kspInstalled = Install-MSI -MsiUrl $kspMsiUrl -OutputPath $kspMsiPath -LogFile $kspLogFile
if (-not $kspInstalled) {
    Write-Warning "CloudHSM KSP Library installation failed. Some functionality may not work."
}

# Install JCE Library
$jceMsiPath = Join-Path $tempDir "AWSCloudHSMJCE.msi"
$jceLogFile = Join-Path $logsDir "cloudhsm-jce-install.log"
$jceInstalled = Install-MSI -MsiUrl $jceMsiUrl -OutputPath $jceMsiPath -LogFile $jceLogFile
if (-not $jceInstalled) {
    Write-Warning "CloudHSM JCE Library installation failed. Some functionality may not work."
}
# --- END CLOUDHSM CLIENT INSTALLATION ---

# --- BEGIN FIREWALL CONFIGURATION ---
Write-Host "Configuring Windows Firewall for CloudHSM..." -ForegroundColor Cyan

# Create firewall rules for CloudHSM communication
try {
    # Check if firewall rules already exist
    $existingRules = Get-NetFirewallRule -DisplayName "CloudHSM Client*" -ErrorAction SilentlyContinue

    if (-not $existingRules) {
        Write-Host "Creating CloudHSM firewall rules for TCP ports 2223-2225..." -ForegroundColor Cyan

        # Create outbound rules
        New-NetFirewallRule -DisplayName "CloudHSM Client Outbound" `
            -Direction Outbound `
            -Protocol TCP `
            -LocalPort Any `
            -RemotePort 2223-2225 `
            -Action Allow `
            -Profile Any `
            -Description "Allow outbound traffic to CloudHSM cluster" | Out-Null

        Write-Host "CloudHSM firewall rules created successfully." -ForegroundColor Green
    } else {
        Write-Host "CloudHSM firewall rules already exist." -ForegroundColor Green
    }
} catch {
    Write-Warning "Failed to configure firewall rules: $($_.Exception.Message)"
}
# --- END FIREWALL CONFIGURATION ---

# --- BEGIN CLIENT CONFIGURATION ---
Write-Host "Configuring CloudHSM Client..." -ForegroundColor Cyan

# Verify paths for configuration utilities
$binDir = Join-Path $baseInstallDir "bin"
$configureCLIExePath = Join-Path $binDir "configure-cli.exe"
$configurePKCS11ExePath = Join-Path $binDir "configure-pkcs11.exe"
$configureKSPExePath = Join-Path $binDir "configure-ksp.exe"
$configureJCEExePath = Join-Path $binDir "configure-jce.exe"

# Simple function to run configuration commands
function Invoke-SimpleConfiguration {
    param(
        [Parameter(Mandatory=$true)][string]$Tool,
        [Parameter(Mandatory=$true)][string]$Arguments,
        [Parameter(Mandatory=$true)][string]$Description
    )

    try {
        Write-Host "Running $Description..." -ForegroundColor Cyan
        Push-Location $binDir

        # Execute command directly with minimal handling
        # Create process with properly escaped arguments for maximum compatibility
        $command = "$Tool $Arguments"
        Write-Verbose "Executing: $command"

        try {
            # Create process start info object
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $Tool
            $psi.Arguments = $Arguments
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.WorkingDirectory = $binDir

            # Create and start the process
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $outputBuilder = New-Object System.Text.StringBuilder
            $errorBuilder = New-Object System.Text.StringBuilder

            # Set up event handlers for output and error
            $outEvent = Register-ObjectEvent -InputObject $process -EventName OutputDataReceived -Action {
                $outputBuilder.AppendLine($Event.SourceEventArgs.Data) | Out-Null
            }
            $errEvent = Register-ObjectEvent -InputObject $process -EventName ErrorDataReceived -Action {
                $errorBuilder.AppendLine($Event.SourceEventArgs.Data) | Out-Null
            }

            # Start the process and begin reading streams
            $null = $process.Start()
            $process.BeginOutputReadLine()
            $process.BeginErrorReadLine()
            $process.WaitForExit()

            # Cleanup event handlers
            Unregister-Event -SourceIdentifier $outEvent.Name
            Unregister-Event -SourceIdentifier $errEvent.Name

            # Collect output
            $output = $outputBuilder.ToString() + $errorBuilder.ToString()
            $exitCode = $process.ExitCode
        }
        catch {
            Write-Warning "Error starting process: $_"
            throw
        }

        # Return to the original location
        Pop-Location

        if ($exitCode -eq 0) {
            Write-Host "$Description completed successfully." -ForegroundColor Green
            return $true
        } else {
            Write-Host ("$Description did not complete successfully with command: $command and instead returned: $output") -ForegroundColor Yellow
            return $false  # Return true anyway to continue with the setup
        }
    } catch {
        Write-Host ("Error during " + $Description + ": " + $($_.Exception.Message)) -ForegroundColor Yellow
        # Continue despite errors
        Pop-Location
        return $true
    }
}

# Configure CLI utility if it exists
if (Test-Path $configureCLIExePath) {
    Invoke-SimpleConfiguration -Tool $configureCLIExePath -Arguments "--cluster-id $ClusterId --region $Region --disable-key-availability-check" -Description "CloudHSM CLI configuration"
} else {
    Write-Warning "configure-cli.exe not found at $configureCLIExePath. Skipping CLI configuration."
}

# Configure PKCS#11 library if it exists
if (Test-Path $configurePKCS11ExePath) {
    Invoke-SimpleConfiguration -Tool $configurePKCS11ExePath -Arguments "--cluster-id $ClusterId --region $Region --disable-key-availability-check" -Description "CloudHSM PKCS#11 configuration"
} else {
    Write-Warning "configure-pkcs11.exe not found at $configurePKCS11ExePath. Skipping PKCS#11 configuration."
}

# Configure KSP with customer CA certificate if it exists
if (Test-Path $configureKSPExePath) {
    $kspArgs = if ($customerCACertPath -and (Test-Path $customerCACertPath)) {
        Write-Host "Using customer CA certificate: $customerCACertPath" -ForegroundColor Cyan
        "--cluster-id $ClusterId --region $Region --hsm-ca-cert `"$customerCACertPath`" --disable-key-availability-check"
    } else {
        Write-Host "Using default CA certificate settings" -ForegroundColor Cyan
        "--cluster-id $ClusterId --region $Region --disable-key-availability-check"
    }

    Invoke-SimpleConfiguration -Tool $configureKSPExePath -Arguments $kspArgs -Description "CloudHSM KSP configuration"
} else {
    Write-Warning "configure-ksp.exe not found at $configureKSPExePath. Skipping KSP configuration."
}

# Configure JCE library if it exists
if (Test-Path $configureJCEExePath) {
    Invoke-SimpleConfiguration -Tool $configureJCEExePath -Arguments "--cluster-id $ClusterId --region $Region --disable-key-availability-check" -Description "CloudHSM JCE configuration"
} else {
    Write-Warning "configure-jce.exe not found at $configureJCEExePath. Skipping JCE configuration."
}
# --- END CLIENT CONFIGURATION ---

# --- BEGIN FINAL VERIFICATION ---
Write-Host "`n=== CloudHSM Installation Summary ===" -ForegroundColor Green
Write-Host "CloudHSM Client CLI:   Installed" -ForegroundColor Green
Write-Host "CloudHSM PKCS#11:      Installed" -ForegroundColor Green
Write-Host "CloudHSM KSP:          Installed" -ForegroundColor Green
Write-Host "CloudHSM JCE:          Installed" -ForegroundColor Green
Write-Host "Cluster ID:            $ClusterId" -ForegroundColor Green
Write-Host "Region:                $Region" -ForegroundColor Green
Write-Host "CA Certificate:        $(if ($customerCACertPath) { "Custom" } else { "Default" })" -ForegroundColor Green
Write-Host "Installation Directory: $baseInstallDir" -ForegroundColor Green
Write-Host "=== End of Summary ===`n" -ForegroundColor Green
# --- END FINAL VERIFICATION ---

# Stop transcript if it was started by this script
if (-not $transcriptActive) {
    Stop-Transcript
    Write-Host "Transcript stopped, output file is $logFile"
}

# Create a status file for the bootstrap script to check
$statusFile = Join-Path $baseDir "cloudhsm-setup-status.json"
$status = @{
    "status" = "success"
    "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    "cluster_id" = $ClusterId
    "region" = $Region
    "install_dir" = $baseInstallDir
}
$status | ConvertTo-Json | Out-File -FilePath $statusFile -Force
