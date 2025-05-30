#
# CloudHSM-Utils.psm1
# Common utility functions for CloudHSM scripts
#

# --- BEGIN ENVIRONMENT CHECK FUNCTIONS ---
function Test-CloudHSMAdminPrivileges {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CloudHSMWindowsVersion {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$false)][int]$MinimumMajorVersion = 10,
        [Parameter(Mandatory=$false)][int]$MinimumMinorVersion = 0
    )
    
    $osInfo = Get-CimInstance Win32_OperatingSystem
    $version = [Version]$osInfo.Version
    
    # Require Windows 10/Server 2016 or higher by default
    if ($version.Major -lt $MinimumMajorVersion) {
        return $false
    }
    
    if ($version.Major -eq $MinimumMajorVersion -and $version.Minor -lt $MinimumMinorVersion) {
        return $false
    }
    
    return $true
}

function Test-CloudHSMDiskSpace {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][long]$RequiredSpaceGB = 10
    )
    
    $drive = (Get-Item $Path).PSDrive
    $freeSpaceGB = $drive.Free / 1GB
    return ($freeSpaceGB -ge $RequiredSpaceGB)
}
# --- END ENVIRONMENT CHECK FUNCTIONS ---

# --- BEGIN AWS UTILITY FUNCTIONS ---
function Initialize-CloudHSMAWSCredentials {
    [CmdletBinding()]
    param()
    
    Write-Host "Starting AWS authentication process via IMDSv2..." -ForegroundColor Cyan
    
    try {
        # Use IMDSv2 token-based authentication
        $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = "300"} `
                                 -Method PUT `
                                 -Uri "http://169.254.169.254/latest/api/token" `
                                 -ErrorAction Stop
        
        $roleName = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} `
                                     -Method GET `
                                     -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/" `
                                     -ErrorAction Stop
        
        $credentials = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} `
                                        -Method GET `
                                        -Uri "http://169.254.169.254/latest/meta-data/iam/security-credentials/$roleName" `
                                        -ErrorAction Stop
        
        Set-AWSCredential -AccessKey $credentials.AccessKeyId `
                          -SecretKey $credentials.SecretAccessKey `
                          -SessionToken $credentials.Token `
                          -StoreAs default
                          
        Write-Host "AWS credentials successfully initialized from instance metadata using IMDSv2" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "Error accessing instance metadata service: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

function Initialize-CloudHSMAWSCliEnvironment {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$false)]
        [switch]$UpdatePath,
        
        [Parameter(Mandatory=$false)]
        [switch]$Quiet
    )
    
    if (-not $Quiet) {
        Write-Host "Locating and initializing AWS CLI..." -ForegroundColor Cyan
    }
    
    $possibleAwsCliPaths = @(
        "aws",
        (Join-Path $env:ProgramFiles "Amazon\AWSCLIV2\aws.exe"),
        (Join-Path $env:ProgramFiles "Amazon\AWSCLI\aws.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Amazon\AWSCLIV2\aws.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Amazon\AWSCLI\aws.exe"),
        (Join-Path $env:ProgramData "chocolatey\bin\aws.exe")
    )
    
    $awsExePath = $null
    $versionInfo = $null
    $pathToAdd = $null
    $isAdmin = Test-CloudHSMAdminPrivileges
    
    foreach ($awsPath in $possibleAwsCliPaths) {
        try {
            if ($awsPath -eq "aws") {
                $versionResult = Invoke-Expression "aws --version" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    if (-not $Quiet) {
                        Write-Host "AWS CLI found in PATH: $($versionResult)" -ForegroundColor Green
                    }
                    $awsExePath = "aws"
                    $versionInfo = $versionResult
                    break
                }
            } 
            elseif (Test-Path $awsPath) {
                $versionResult = & $awsPath --version 2>&1
                if ($LASTEXITCODE -eq 0) {
                    if (-not $Quiet) {
                        Write-Host "AWS CLI found at $($awsPath): $($versionResult)" -ForegroundColor Green
                    }
                    $awsExePath = $awsPath
                    $versionInfo = $versionResult
                    $pathToAdd = Split-Path -Parent $awsPath
                    break
                }
            }
        }
        catch {
            Write-Verbose "Failed to execute AWS CLI at $($awsPath): $($_.Exception.Message)"
        }
    }

    if ($awsExePath) {
        if ($UpdatePath -and $pathToAdd -and $isAdmin) {
            try {
                $systemPath = [System.Environment]::GetEnvironmentVariable('Path', [System.EnvironmentVariableTarget]::Machine)
                $pathEntries = $systemPath -split ';' | Where-Object { $_ -ne '' }

                $normalizedAwsPath = $pathToAdd.TrimEnd('\')
                $pathFound = $false
                foreach ($entry in $pathEntries) {
                    if ($entry.TrimEnd('\') -eq $normalizedAwsPath) {
                        $pathFound = $true
                        break
                    }
                }

                if (-not $pathFound) {
                    if (-not $Quiet) {
                        Write-Host "AWS CLI path '$pathToAdd' not found in system PATH. Adding it..." -ForegroundColor Yellow
                    }
                    $newPath = ($pathEntries + $pathToAdd) -join ';'
                    [System.Environment]::SetEnvironmentVariable('Path', $newPath, [System.EnvironmentVariableTarget]::Machine)
                    if (-not $Quiet) {
                        Write-Host "AWS CLI path added to system PATH. A system restart or new shell session may be required for changes to take effect." -ForegroundColor Green
                    }
                    $env:Path = "$env:Path;$pathToAdd"
                    Write-Verbose "Current process PATH updated."
                } else {
                    if (-not $Quiet) {
                        Write-Host "AWS CLI path '$pathToAdd' is already in the system PATH." -ForegroundColor Cyan
                    }
                }
            } catch {
                Write-Host "Failed to update system PATH: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        if (-not $Quiet) {
            Write-Host "AWS CLI not found or not operational after checking common locations." -ForegroundColor Yellow
            Write-Host "Consider installing the AWS CLI using: 'choco install awscli' or download from https://aws.amazon.com/cli/" -ForegroundColor Yellow
        }
    }
    
    return [PSCustomObject]@{
        Found = ($null -ne $awsExePath)
        Path = $awsExePath
        Version = $versionInfo
        InstallDir = $pathToAdd
    }
}

function Invoke-CloudHSMAWSCommand {
    [CmdletBinding(DefaultParameterSetName = 'CommandString')]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName='CommandString')]
        [string]$Command,
        
        [Parameter(Mandatory=$true, ParameterSetName='ServiceOperation')]
        [string]$Service,
        
        [Parameter(Mandatory=$true, ParameterSetName='ServiceOperation')]
        [string]$Operation,
        
        [Parameter(Mandatory=$false)]
        [string]$Region,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$Parameters = @{},
        
        [Parameter(Mandatory=$false)]
        [switch]$AsJson,
        
        [Parameter(Mandatory=$false)]
        [switch]$PassThru
    )
    
    $awsCliInfo = Initialize-CloudHSMAWSCliEnvironment -Quiet
    if (-not $awsCliInfo.Found) {
        throw "AWS CLI not found. Cannot execute command."
    }
    $awsExePath = $awsCliInfo.Path
    
    $fullCommand = if ($PSCmdlet.ParameterSetName -eq 'CommandString') {
        if ($awsExePath -eq "aws") {
            "aws $Command"
        }
        else {
            "& `"$($awsExePath)`" $Command"
        }
    }
    else {
        $cmdArgs = "$Service $Operation"
        
        foreach ($param in $Parameters.GetEnumerator()) {
            $cmdArgs += " --$($param.Key) `"$($param.Value)`""
        }
        
        if ($Region) {
            $cmdArgs += " --region $Region"
        }
        
        if ($awsExePath -eq "aws") {
            "aws $cmdArgs"
        }
        else {
            "& `"$($awsExePath)`" $cmdArgs"
        }
    }
    
    if ($AsJson -and -not $fullCommand.Contains(" --output ")) {
        $fullCommand += " --output json"
    }
    
    Write-Host "Executing AWS CLI command: $fullCommand" -ForegroundColor Cyan
    try {
        $result = Invoke-Expression $fullCommand 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            throw ("AWS CLI command failed with exit code {0}: {1}" -f $LASTEXITCODE, $result)
        }
        
        if ($AsJson -and $result -and $result.Trim().StartsWith("{")) {
            try {
                $jsonResult = $result | ConvertFrom-Json
                
                if ($PassThru) {
                    return $jsonResult
                }
                return $true
            }
            catch {
                Write-Host "Failed to parse JSON response: $($_.Exception.Message)" -ForegroundColor Yellow
                if ($PassThru) {
                    return $result
                }
                return $true
            }
        }
        
        if ($PassThru) {
            return $result
        }
        return $true
    }
    catch {
        Write-Host "Error executing AWS CLI command: $($_.Exception.Message)" -ForegroundColor Red
        if ($PassThru) {
            return $null
        }
        return $false
    }
}

function Get-CloudHSMFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Source,
        [Parameter(Mandatory=$true)][string]$Destination,
        [Parameter(Mandatory=$false)][string]$Region = $env:AWS_REGION,
        [Parameter(Mandatory=$false)][string]$Description = "file",
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3,
        [Parameter(Mandatory=$false)][int]$RetryDelaySeconds = 5
    )
    
    $isS3Path = $Source -like "s3://*"
    $isHttpPath = $Source -like "http*://*"
    
    Write-Host "Downloading $Description from $Source to $Destination" -ForegroundColor Cyan
    
    $retryCount = 0
    $success = $false
    
    while (-not $success -and $retryCount -le $MaxRetries) {
        if ($retryCount -gt 0) {
            Write-Host "Retry attempt $retryCount for downloading $Description" -ForegroundColor Yellow
            Start-Sleep -Seconds ($RetryDelaySeconds * $retryCount)
        }
        
        $retryCount++
        
        try {
            if ($isS3Path) {
                $s3Uri = New-Object System.Uri($Source)
                $bucketName = $s3Uri.Host
                $key = $s3Uri.AbsolutePath.TrimStart('/')
                
                try {
                    Write-Verbose "Downloading using AWS Tools for PowerShell: s3://$bucketName/$key"
                    # Import AWS PowerShell module if not already loaded
                    if (-not (Get-Module -Name AWSPowerShell -ErrorAction SilentlyContinue)) {
                        Write-Host "Importing AWSPowerShell module..." -ForegroundColor Yellow
                        Import-Module AWSPowerShell -ErrorAction Stop
                        Initialize-AWSDefaultConfiguration -InstanceProfile
                    }
                    
                    Read-S3Object -BucketName $bucketName -Key $key -File $Destination -Region $Region -ErrorAction Stop
                    $success = $true
                } catch {
                    Write-Host "S3 PowerShell module failed, trying AWS CLI: $($_.Exception.Message)" -ForegroundColor Yellow
                    Invoke-CloudHSMAWSCommand -Command "s3 cp s3://$bucketName/$key $Destination --region $Region" -PassThru | Out-Null
                    
                    if (Test-Path $Destination) {
                        $success = $true
                    } else {
                        throw "AWS CLI S3 download failed"
                    }
                }
            } 
            elseif ($isHttpPath) {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                
                try {
                    Write-Verbose "Downloading using Invoke-WebRequest: $Source"
                    Invoke-WebRequest -Uri $Source -OutFile $Destination -UseBasicParsing -ErrorAction Stop
                    $success = $true
                }
                catch {
                    try {
                        Write-Host "Invoke-WebRequest failed, trying WebClient: $($_.Exception.Message)" -ForegroundColor Yellow
                        $webClient = New-Object System.Net.WebClient
                        $webClient.DownloadFile($Source, $Destination)
                        $success = $true
                    }
                    catch {
                        try {
                            Write-Host "WebClient failed, trying curl.exe: $($_.Exception.Message)" -ForegroundColor Yellow
                            $curlPath = Get-Command curl.exe -ErrorAction Stop | Select-Object -ExpandProperty Source
                            $curlArgs = @("-L", "-o", "`"$Destination`"", "--fail", "--silent", $Source)
                            Start-Process -FilePath $curlPath -ArgumentList $curlArgs -Wait -NoNewWindow
                            
                            if (Test-Path $Destination) {
                                $success = $true
                            } else {
                                throw "curl.exe download failed or file is empty"
                            }
                        }
                        catch {
                            if ($retryCount -ge $MaxRetries) {
                                throw "All HTTP download methods failed: $($_.Exception.Message)"
                            }
                        }
                    }
                }
            }
            else {
                Copy-Item -Path $Source -Destination $Destination -Force -ErrorAction Stop
                $success = $true
            }
            
            if ($success -and (Test-Path $Destination)) {
                $fileInfo = Get-Item $Destination
                if ($fileInfo.Length -eq 0) {
                    Remove-Item $Destination -Force -ErrorAction SilentlyContinue
                    throw "Download completed but file is empty"
                }
            } else {
                throw "Download appeared to succeed but file does not exist at $Destination"
            }
        }
        catch {
            if ($retryCount -ge $MaxRetries) {
                Write-Host "Failed to download $Description after $MaxRetries attempts: $($_.Exception.Message)" -ForegroundColor Red
                return $false
            }
            
            Write-Host "Download attempt $retryCount failed: $($_.Exception.Message)" -ForegroundColor Yellow
            
            if (Test-Path $Destination) {
                Remove-Item $Destination -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    if ($success) {
        Write-Host "$Description downloaded successfully to $Destination" -ForegroundColor Green
        return $true
    }
    
    return $false
}
# --- END AWS UTILITY FUNCTIONS ---

# --- BEGIN RETRY LOGIC FUNCTIONS ---
function Invoke-CloudHSMWithRetry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)][scriptblock]$ScriptBlock,
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3,
        [Parameter(Mandatory=$false)][int]$RetryDelaySeconds = 5,
        [Parameter(Mandatory=$false)][string]$OperationName = "Operation"
    )

    $retryCount = 0
    $completed = $false
    $errorDetails = $null

    while (-not $completed -and $retryCount -lt $MaxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Host "Retry attempt $retryCount for $OperationName" -ForegroundColor Yellow
                Start-Sleep -Seconds ($RetryDelaySeconds * [Math]::Min($retryCount, 5))
            }

            $result = Invoke-Command -ScriptBlock $ScriptBlock
            $completed = $true
            return $result
        }
        catch {
            $errorDetails = $_
            $retryCount++
            
            if ($retryCount -ge $MaxRetries) {
                Write-Host "All $MaxRetries retry attempts for $OperationName failed." -ForegroundColor Red
                throw $errorDetails
            }
            
            Write-Host "Error during $OperationName (attempt $retryCount/$MaxRetries): $($errorDetails.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
# --- END RETRY LOGIC FUNCTIONS ---

# --- BEGIN MSI INSTALLER FUNCTIONS ---
function Install-CloudHSMMSI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$ComponentName,
        [Parameter(Mandatory=$true)][string]$MsiUrl,
        [Parameter(Mandatory=$false)][string]$InstallDir = "C:\CloudHSM",
        [Parameter(Mandatory=$false)][string]$LogDir = "C:\CloudHSM\logs",
        [Parameter(Mandatory=$false)][hashtable]$AdditionalArgs = @{},
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3
    )
    
    if (-not (Test-Path $LogDir)) {
        New-Item -Path $LogDir -ItemType Directory -Force | Out-Null
    }
    
    $msiFileName = Split-Path $MsiUrl -Leaf
    $logSuffix = $ComponentName.ToLower() -replace '\s+', '-'
    $msiLocalPath = Join-Path $env:TEMP $msiFileName
    $logFilePath = Join-Path $LogDir "$logSuffix-install.log"
    
    try {
        $downloadSuccess = Get-CloudHSMFile -Source $MsiUrl -Destination $msiLocalPath `
                                     -Description "$ComponentName MSI" -MaxRetries $MaxRetries
        
        if (-not $downloadSuccess) {
            # Add specific logging here
            $downloadErrorMsg = "Failed to download $ComponentName MSI from $MsiUrl"
            Write-Host $downloadErrorMsg -ForegroundColor Red
            # Ensure the error is thrown so the catch block handles it
            throw $downloadErrorMsg
        }
        
        Write-Host "Installing $ComponentName..." -ForegroundColor Cyan
        $msiexecArgs = @(
            "/i", "`"$msiLocalPath`"",
            "/quiet",
            "/norestart",
            "/log", "`"$logFilePath`""
        )
        
        if ($InstallDir) {
            $msiexecArgs += "INSTALLDIR=`"$InstallDir`""
        }
        
        foreach ($key in $AdditionalArgs.Keys) {
            $msiexecArgs += "$key=`"$($AdditionalArgs[$key])`""
        }
        
        $msiexecArgsString = $msiexecArgs -join ' '
        Write-Host "Attempting to run: msiexec.exe $msiexecArgsString" -ForegroundColor Cyan # Added logging
        
        $installSuccess = Invoke-CloudHSMWithRetry -ScriptBlock {
            Write-Host "Inside Invoke-CloudHSMWithRetry: Starting msiexec process..." -ForegroundColor Magenta # Added logging
            $process = Start-Process msiexec.exe -ArgumentList $msiexecArgs -Wait -NoNewWindow -PassThru
            $exitCode = $process.ExitCode
            Write-Host "Inside Invoke-CloudHSMWithRetry: msiexec process finished with exit code: $exitCode" -ForegroundColor Magenta # Added logging
            
            # Check if MSI log file was created
            if (Test-Path $logFilePath) {
                Write-Host "Inside Invoke-CloudHSMWithRetry: MSI log file found at $logFilePath" -ForegroundColor Magenta # Added logging
            } else {
                Write-Host "Inside Invoke-CloudHSMWithRetry: MSI log file NOT found at $logFilePath" -ForegroundColor Magenta # Added logging
            }

            if ($exitCode -ne 0) {
                # Try reading the log file content if it exists, even on failure
                if (Test-Path $logFilePath) {
                    try {
                        $logContent = Get-Content $logFilePath -Raw -ErrorAction SilentlyContinue
                        if ($logContent) {
                             Write-Host "MSI Log ($logFilePath) Content Snippet (Last 10 lines):" -ForegroundColor Yellow
                             ($logContent -split '\r?\n')[-10..-1] | ForEach-Object { Write-Host "  $_" -ForegroundColor Yellow }
                        }
                    } catch { Write-Host "Could not read MSI log content: $($_.Exception.Message)" -ForegroundColor Yellow }
                }
                throw "MSI installation failed with exit code: $exitCode"
            }
            return $true
        } -MaxRetries $MaxRetries -OperationName "$ComponentName installation" -ErrorAction Stop
        
        Write-Host "$ComponentName installation reported success." -ForegroundColor Green # Changed message slightly
        return $true
    } 
    catch {
        Write-Host "Failed to install $($ComponentName): $($_.Exception.Message)" -ForegroundColor Red
        if (Test-Path $logFilePath) {
            Write-Host "Check install log for details: $logFilePath" -ForegroundColor Yellow
        }
        return $false
    } 
    finally {
        if (Test-Path $msiLocalPath) {
            Write-Verbose "Removing temporary MSI file: $msiLocalPath"
            Remove-Item $msiLocalPath -Force -ErrorAction SilentlyContinue
        }
    }
}
# --- END MSI INSTALLER FUNCTIONS ---

# --- BEGIN METADATA ACCESS FUNCTIONS ---
function Get-EC2InstanceMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$false)][int]$TokenTTLSeconds = 300
    )
    
    try {
        # Get IMDSv2 token
        $token = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token-ttl-seconds" = $TokenTTLSeconds} `
                                 -Method PUT `
                                 -Uri "http://169.254.169.254/latest/api/token" `
                                 -ErrorAction Stop
        
        # Use token to get metadata
        $metadata = Invoke-RestMethod -Headers @{"X-aws-ec2-metadata-token" = $token} `
                                     -Method GET `
                                     -Uri "http://169.254.169.254/latest/meta-data/$Path" `
                                     -ErrorAction Stop
        
        return $metadata
    }
    catch {
        Write-Host "Error accessing instance metadata at path '$Path': $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}

function Get-EC2InstanceRegion {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)][int]$TokenTTLSeconds = 300
    )
    
    $region = Get-EC2InstanceMetadata -Path "placement/region" -TokenTTLSeconds $TokenTTLSeconds
    if (-not $region) {
        Write-Host "Failed to determine instance region from metadata service" -ForegroundColor Yellow
        return $env:AWS_REGION
    }
    return $region
}

function Get-EC2InstanceId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory=$false)][int]$TokenTTLSeconds = 300
    )
    
    $instanceId = Get-EC2InstanceMetadata -Path "instance-id" -TokenTTLSeconds $TokenTTLSeconds
    if (-not $instanceId) {
        Write-Host "Failed to determine instance ID from metadata service" -ForegroundColor Yellow
    }
    return $instanceId
}
# --- END METADATA ACCESS FUNCTIONS ---

Export-ModuleMember -Function Test-CloudHSMAdminPrivileges
Export-ModuleMember -Function Test-CloudHSMWindowsVersion
Export-ModuleMember -Function Test-CloudHSMDiskSpace
Export-ModuleMember -Function Initialize-CloudHSMAWSCredentials
Export-ModuleMember -Function Initialize-CloudHSMAWSCliEnvironment
Export-ModuleMember -Function Invoke-CloudHSMAWSCommand
Export-ModuleMember -Function Get-CloudHSMFile
Export-ModuleMember -Function Invoke-CloudHSMWithRetry
Export-ModuleMember -Function Install-CloudHSMMSI
Export-ModuleMember -Function Get-EC2InstanceMetadata
Export-ModuleMember -Function Get-EC2InstanceRegion
Export-ModuleMember -Function Get-EC2InstanceId
