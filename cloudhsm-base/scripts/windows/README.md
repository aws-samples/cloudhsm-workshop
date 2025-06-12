# Windows CloudHSM Code Signing Setup

This document describes a suite of PowerShell scripts designed to automate the setup of a Windows environment for code signing using AWS CloudHSM.

## Overview

The scripts perform the following tasks:
- Install necessary prerequisites (AWS Tools, AWS CLI, Chocolatey, Windows Features).
- Install and configure the AWS CloudHSM client and Key Storage Provider (KSP).
- Install development dependencies (Windows SDK, .NET, Build Tools).
- Install and configure Microsoft SignTool for CloudHSM integration.
- Provide utilities for generating Certificate Signing Requests (CSRs) and signing files.

## Prerequisites

- **Windows Instance**: An EC2 Windows Server instance (2016, 2019, or 2022).
- **IAM Role**: The instance must have an IAM role attached with permissions for:
  - `cloudhsm:DescribeClusters`
  - `secretsmanager:GetSecretValue` (for `cloudhsm/<ClusterId>/crypto-user`)
  - `ssm:GetParameter` (if using SSM Parameters)
  - `s3:GetObject` (for the specified `ScriptsPath` if using S3)
- **SSM Agent**: AWS Systems Manager Agent must be installed and running.
- **Connectivity**:
  - Network connectivity from the instance to the CloudHSM cluster IPs (ENIs) on ports 2223-2225.
  - Internet connectivity for downloading dependencies (e.g., Chocolatey packages, AWS Tools modules) if not pre-installed or cached.
- **Administrator Access**: Access to the instance with Administrator privileges (e.g., via Fleet Manager or RDP).

## Script Execution

The primary script is `bootstrap.ps1`, which orchestrates the execution of the other setup scripts.

### Running Bootstrap

**Important:** Run PowerShell as Administrator.

The bootstrap script can fetch the other scripts from either a private S3 bucket (using the instance's IAM role) or a local directory.

#### From S3:

Requires the instance role to have `s3:GetObject` permission on `s3://<your-bucket>/<your-prefix>/*`.

```powershell
# Ensure bootstrap.ps1 is available locally (e.g., downloaded via UserData)
powershell -ExecutionPolicy Bypass -File C:\Path\To\bootstrap.ps1 `
    -ClusterId <your-hsm-cluster-id> `
    -ScriptsPath "s3://<your-bucket>/<your-prefix>" `
    [-Region <aws-region>]
```
*   Replace `<your-hsm-cluster-id>` with your actual CloudHSM cluster ID (e.g., `cluster-xxxxxxxxxxxx`).
*   Replace `s3://<your-bucket>/<your-prefix>` with the S3 path containing the scripts (`install-prerequisites.ps1`, `setup-cloudhsm.ps1`, etc.).
*   Bootstrap will attempt to install the `AWS.Tools.S3` PowerShell module if it's not already present.
*   Authentication to S3 uses the instance's attached IAM role via the `Read-S3Object` cmdlet.
*   The `-Region` parameter is optional if the `AWS_REGION` environment variable is set.

#### From Local Path:

```powershell
# Ensure all scripts are in the specified local directory
powershell -ExecutionPolicy Bypass -File C:\Path\To\bootstrap.ps1 `
    -ClusterId <your-hsm-cluster-id> `
    -ScriptsPath "C:\path\to\all\scripts" `
    [-Region <aws-region>]
```
*   Replace `C:\path\to\all\scripts` with the directory containing all the `.ps1` scripts.

### Script Sequence

`bootstrap.ps1` executes the following scripts in order:

1.  **`install-prerequisites.ps1`**:
    *   Installs AWS Tools for PowerShell (`AWS.Tools.Installer`, `AWS.Tools.EC2`, `AWS.Tools.SecretsManager`, `AWS.Tools.SimpleSystemsManagement`).
    *   Installs AWS CLI using Chocolatey.
    *   Enables required Windows features (`RSAT-AD-Tools`, `Web-Server`, `Web-Scripting-Tools`).
    *   Installs Chocolatey package manager if not present.
    *   Ensures the SSM Agent service (`AmazonSSMAgent`) is running.
2.  **`setup-cloudhsm.ps1`**:
    *   Retrieves CloudHSM crypto user credentials from Secrets Manager (`cloudhsm/<ClusterId>/crypto-user`).
    *   Downloads and installs the AWS CloudHSM client MSI.
    *   Configures the CloudHSM client using the retrieved credentials and cluster information.
    *   Configures Windows Firewall to allow outbound traffic on TCP ports 2223-2225.
    *   Creates a Windows Event Log source (`CloudHSM-CodeSigning`) for logging.
    *   Registers the CloudHSM Key Storage Provider (KSP) DLL (`cloudhsm-ksp.dll`).
    *   Configures `wintrust.dll.ini` for SignTool integration with CloudHSM KSP.
    *   Adds the SignTool directory (`C:\SignTool`) to the system PATH.
3.  **`install-dependencies.ps1`**:
    *   Installs the Windows SDK (currently targets 10.0.22621.0).
    *   Installs .NET Framework 4.8 Developer Pack via Chocolatey.
    *   Installs Visual Studio 2022 Build Tools via Chocolatey (includes MSBuild, VC++ Tools).
    *   Installs NuGet CLI via Chocolatey.
    *   Installs supporting PowerShell modules (`PSScriptAnalyzer`, `PowerShellGet`, `PSReadLine`).
4.  **`install-signtool.ps1`**:
    *   Requires a `signing-tools` subfolder within the `ScriptsPath` (e.g., `s3://<bucket>/<prefix>/signing-tools/` or `C:\path\to\scripts\signing-tools\`).
    *   Copies `signtool.exe` and required DLLs (e.g., `wintrust.dll`) from the `signing-tools` subfolder to `C:\SignTool`.
    *   Downloads and installs Visual C++ 2022 Runtimes (x86 & x64).
    *   Optionally installs and configures Office SIP components (requires `msosip.dll`, `msosipx.dll`, `vbe7.dll` in the `signing-tools` subfolder).

## Code Signing Operations

### 1. Generate CSR (initialize-code-signing.ps1)

After the bootstrap process completes successfully, generate a Certificate Signing Request (CSR) using the CloudHSM KSP.

```powershell
powershell -ExecutionPolicy Bypass -File C:\CloudHSM\initialize-code-signing.ps1 `
    -ClusterId <your-hsm-cluster-id> `
    [-Region <aws-region>]
```

*   This script retrieves the crypto user credentials again.
*   It generates a `request.inf` file defining the certificate parameters (RSA 3072, SHA256, Code Signing EKU) and specifies the `CloudHSM Key Storage Provider`.
*   It uses `certreq.exe -new` to generate the private key within the HSM and output the CSR file to `C:\CloudHSM\request.csr`.
*   **Submit this CSR to your Certificate Authority (CA) to obtain the signed certificate.**

### 2. Install Certificate

Once you receive the signed certificate file (e.g., `mycert.cer`) from your CA, install it into the **Local Machine** certificate store:

```powershell
certutil -addstore My mycert.cer
```
*   Ensure the full certificate chain (including intermediate and root CAs) is also present in the appropriate stores (`CA` and `Root`) on the machine.

### 3. Sign Files (sign-code.ps1)

Use the `sign-code.ps1` script to sign executable files or other supported types using the HSM-backed certificate.

```powershell
powershell -ExecutionPolicy Bypass -File C:\CloudHSM\sign-code.ps1 `
    -FilePath C:\path\to\your\application.exe `
    -CertificateThumbprint <your-certificate-thumbprint> `
    [-TimestampServer <timestamp-server-url>]
```

*   Replace `<your-certificate-thumbprint>` with the thumbprint of the certificate installed in step 2. You can find this using `Get-ChildItem Cert:\LocalMachine\My`.
*   The `-TimestampServer` parameter is optional but highly recommended. A common default is `http://timestamp.digicert.com`.
*   The script verifies that the specified certificate uses the CloudHSM KSP before attempting to sign.
*   It uses `signtool.exe` with the `/sm` (use machine store) and `/sha1 <thumbprint>` parameters to select the certificate.
*   It performs verification (`signtool.exe verify /v /pa`) after signing.

## Robustness and Idempotency

*   **Administrator Privileges**: All scripts require administrative privileges to run correctly.
*   **Error Handling**: Scripts incorporate `try-catch` blocks and detailed logging for better error diagnosis. Bootstrap script tracks failures in dependencies.
*   **Idempotency**: Scripts are designed to be run multiple times without causing errors. They check for existing installations or configurations before attempting to create them.
*   **Logging**: Each script logs its actions to a corresponding file in `C:\CloudHSM\`. The `Write-Log` function includes timestamps and log levels (Info, Warning, Error).

## Security Considerations

*   **Key Security**: Private keys are generated and stored securely within the CloudHSM cluster and never leave it.
*   **Credentials**: CloudHSM user credentials are retrieved securely from AWS Secrets Manager.
*   **Access Control**: Instance access should be restricted (e.g., using Systems Manager Fleet Manager). The IAM role attached to the instance should follow the principle of least privilege.
*   **Firewall**: Windows Firewall rules limit outbound communication to only the necessary CloudHSM ports.
*   **Event Logging**: The `CloudHSM-CodeSigning` event source provides an audit trail for setup activities.

## Troubleshooting

1.  **Check Logs**: Examine the log files in `C:\CloudHSM\` for detailed error messages:
    *   `bootstrap.log`
    *   `install-prerequisites.log`
    *   `setup-cloudhsm.log`
    *   `install-dependencies.log`
    *   `install-signtool.log` (check MSI log too: `cli_install.log`)
2.  **Admin Privileges**: Ensure you are running PowerShell as Administrator.
3.  **CloudHSM Connectivity**:
    *   Verify firewall rules (`Get-NetFirewallRule -DisplayName "Allow CloudHSM Outbound"`).
    *   Check CloudHSM client configuration (`C:\ProgramData\Amazon\CloudHSM\data\customerCA.crt` should exist).
    *   Confirm network path to HSM ENIs on ports 2223-2225.
4.  **Credentials**: Verify the secret `cloudhsm/<ClusterId>/crypto-user` exists in Secrets Manager and contains valid JSON (`{"username":"...", "password":"..."}`).
5.  **S3 Access (if using S3 ScriptsPath)**:
    *   Verify the `ScriptsPath` format is `s3://<bucket>/<prefix>`.
    *   Check the instance's IAM role has `s3:GetObject` permissions for `s3://<bucket>/<prefix>/*`.
    *   Ensure the `AWS.Tools.S3` module was installed and imported successfully (check `bootstrap.log`).
6.  **Signing Issues**:
    *   Verify the certificate is installed in `Cert:\LocalMachine\My` (`Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq '<thumbprint>'}`).
    *   Verify the certificate uses the correct KSP: `(Get-Item Cert:\LocalMachine\My\<thumbprint>).PrivateKey.CspKeyContainerInfo.ProviderName` should be `CloudHSM Key Storage Provider`.
    *   Ensure `C:\SignTool` is in the system PATH.
    *   Check `wintrust.dll.ini` in `C:\SignTool`.
    *   Ensure all dependencies (SDK, runtimes) are installed correctly.
    *   Check that `signtool.exe` and its dependencies exist in the `signing-tools` subfolder specified by `ScriptsPath`.
7.  **Event Logs**: Check the Windows Application Event Log for messages from the `CloudHSM-CodeSigning` source.
