import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import {
    IVpc,
    Instance,
    InstanceType,
    UserData,
    MachineImage,
    SecurityGroup,
    InterfaceVpcEndpoint,
    GatewayVpcEndpoint,
    Peer,
    Port,
    KeyPair,
} from 'aws-cdk-lib/aws-ec2';
import { VpcEndpointWaiter } from './vpc-endpoint-waiter';
import { StringParameter } from 'aws-cdk-lib/aws-ssm';
import { Secret } from 'aws-cdk-lib/aws-secretsmanager';
import { LogGroup, RetentionDays } from 'aws-cdk-lib/aws-logs';
import { Asset } from 'aws-cdk-lib/aws-s3-assets';
import * as path from 'path';
import * as fs from 'fs';
import * as iam from 'aws-cdk-lib/aws-iam';

export interface WindowsServerStackProps extends cdk.StackProps {
    vpc: IVpc;
    subnetId: string;
    instanceType: string;
    keyPairName: string;
    windowsAmiParameter: string;
    securityGroup: SecurityGroup;
    cloudHsmClusterId: string;
    assetsBucketName?: string;
    assetsBucketPrefix?: string;
    // Add VPC endpoint references from the network stack
    ssmEndpoint: InterfaceVpcEndpoint;
    ec2MessagesEndpoint: InterfaceVpcEndpoint;
    ssmmessagesEndpoint: InterfaceVpcEndpoint;
    s3Endpoint: GatewayVpcEndpoint;
    githubRepositoryUrPath: string;
}

export class WindowsServerStack extends cdk.Stack {
    public readonly instance: Instance;

    // VPC Endpoints
    public readonly ssmEndpoint: InterfaceVpcEndpoint;
    public readonly ec2MessagesEndpoint: InterfaceVpcEndpoint;
    public readonly ssmmessagesEndpoint: InterfaceVpcEndpoint;
    public readonly s3Endpoint: GatewayVpcEndpoint;
    public readonly createdKeyPair?: KeyPair;

    constructor(scope: Construct, id: string, props: WindowsServerStackProps) {
        super(scope, id, props);

        // We don't need to create SSM Default Management Role inside this stack anymore
        // It's now handled by the WindowsSystemsManagerQuickSetupStack

        // Use the VPC endpoints passed from the network stack
        this.ssmEndpoint = props.ssmEndpoint;
        this.ec2MessagesEndpoint = props.ec2MessagesEndpoint;
        this.ssmmessagesEndpoint = props.ssmmessagesEndpoint;
        this.s3Endpoint = props.s3Endpoint;

        const githubUrlRawPath = `https://raw.githubusercontent.com/${props.githubRepositoryUrPath}`;

        // If keyPairName is undefined, create a new KeyPair in the current stack
        if (!props.keyPairName) {
            cdk.Annotations.of(this).addWarning(
                'No key pair name provided. A new key pair will be created in the Windows Server stack.',
            );
            this.createdKeyPair = new KeyPair(this, 'WindowsServerKeyPair', {
                keyPairName: `cloudhsm-workshop-keypair-${this.region}-${this.account}`,
            });
            props.keyPairName = this.createdKeyPair.keyPairName;
        }

        // Create a VPC endpoint waiter within this stack to ensure endpoints are fully available before the instance is created
        // The waiter uses a custom resource that checks if endpoints are in 'available' state
        // and verifies that DNS resolution and TCP connectivity work for the endpoint services
        const vpcEndpointWaiter = new VpcEndpointWaiter(this, 'VpcEndpointWaiter', {
            endpoints: [this.ssmEndpoint, this.ec2MessagesEndpoint, this.ssmmessagesEndpoint, this.s3Endpoint],
            vpc: props.vpc,
            region: this.region || cdk.Stack.of(this).region,
            timeoutSeconds: 900, // 15 minutes timeout
        });

        // Create the instance role with enhanced permissions for SSM agent registration
        const windowsInstanceRole = new cdk.aws_iam.Role(this, 'WindowsServerInstanceRole', {
            assumedBy: new cdk.aws_iam.ServicePrincipal('ec2.amazonaws.com'),
            managedPolicies: [
                cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedInstanceCore'),
                cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonS3ReadOnlyAccess'),
                // Adding additional SSM policies to ensure proper registration
                cdk.aws_iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMPatchAssociation'),
            ],
        });

        // Add permissions for SSM agent to register with SSM service and for Fleet Manager functionality
        windowsInstanceRole.addToPolicy(
            new iam.PolicyStatement({
                actions: [
                    'iam:PassRole',
                    'iam:GetRole',
                    'ssm:UpdateInstanceInformation',
                    'ssm:ListInstanceAssociations',
                    'ssm:DescribeInstanceProperties',
                    'ssm:DescribeDocumentParameters',
                ],
                resources: [
                    `arn:aws:iam::${this.account}:role/service-role/AWSSystemsManagerDefaultEC2InstanceManagementRole`,
                    '*',
                ],
                effect: iam.Effect.ALLOW,
            }),
        );

        // Add explicit permissions for CloudHSM parameter access and Secrets Manager
        windowsInstanceRole.addToPolicy(
            new iam.PolicyStatement({
                actions: [
                    // Only need Secret Manager access for crypto-user, as confirmed by user
                    'secretsmanager:GetSecretValue',
                ],
                resources: [
                    // Focus only on crypto-user secret
                    `arn:aws:secretsmanager:${this.region}:${this.account}:secret:cloudhsm/${props.cloudHsmClusterId}/crypto-user*`,
                ],
                effect: iam.Effect.ALLOW,
            }),
        );

        // Explicitly create the CloudWatch Log Group
        const logGroup = new LogGroup(this, 'CloudHsmWorkshopLogGroup', {
            logGroupName: '/ec2/windows/cloudhsm-workshop',
            retention: RetentionDays.ONE_WEEK,
            removalPolicy: cdk.RemovalPolicy.DESTROY,
        });

        // Use the provided SSM parameter for the AMI name
        const ami = MachineImage.fromSsmParameter(props.windowsAmiParameter);

        // Create assets for scripts - this packages and uploads them to S3 automatically
        const bootstrapScriptAsset = new Asset(this, 'BootstrapScriptAsset', {
            path: path.join(__dirname, '..', 'scripts', 'windows', 'bootstrap.ps1'),
            // Add a display name for easier identification
        });

        // Add additional script assets as needed
        const assetsDirectory = path.join(__dirname, '..', 'scripts', 'windows');
        const additionalScripts = [
            'CloudHSM-Utils.psm1',
            'check-status.ps1',
            'install-dependencies.ps1',
            'install-prerequisites.ps1',
            'install-signtool.ps1',
            'setup-cloudhsm.ps1',
        ];

        // Create assets for each additional script
        const additionalScriptAssets = additionalScripts.map(
            (scriptName) =>
                new Asset(this, `Asset-${scriptName.replace('.', '-')}`, {
                    path: path.join(assetsDirectory, scriptName),
                }),
        );

        // Explicitly grant read permissions to the instance role for all assets
        bootstrapScriptAsset.grantRead(windowsInstanceRole);
        additionalScriptAssets.forEach((asset) => asset.grantRead(windowsInstanceRole));

        // Extract and expose the S3 bucket and key information from the assets
        const assetBucketName = props.assetsBucketName || bootstrapScriptAsset.s3BucketName;
        const assetObjectKey = bootstrapScriptAsset.s3ObjectKey;
        const assetBucketPrefix = props.assetsBucketPrefix || assetObjectKey.split('/')[0]; // Get the prefix part

        // Output the CDK Assets information for reference
        new cdk.CfnOutput(this, 'AssetsBucketName', {
            value: assetBucketName,
            description: props.assetsBucketName
                ? 'External Workshop Assets S3 bucket'
                : 'CDK Assets S3 bucket containing CloudHSM scripts',
        });

        new cdk.CfnOutput(this, 'AssetsBucketPrefix', {
            value: assetBucketPrefix,
            description: props.assetsBucketPrefix
                ? 'External Workshop Assets prefix'
                : 'CDK Assets prefix/key for CloudHSM scripts',
        });

        // Store the bucket and key info for use elsewhere if needed
        if (props.assetsBucketName !== undefined) {
            // This is a bit of a hack, but allows outside access to the actual bucket name
            (props as any).actualAssetsBucketName = assetBucketName;
        }
        if (props.assetsBucketPrefix !== undefined) {
            // This is a bit of a hack, but allows outside access to the actual prefix
            (props as any).actualAssetsBucketPrefix = assetBucketPrefix;
        }

        // Get deployment version from context or use current timestamp
        const deploymentVersion = this.node.tryGetContext('deploymentVersion') || new Date().toISOString();

        let scriptContent = '';
        // Create a template object with all parameters for script.ps1
        // Use custom assets bucket URL if provided, otherwise use CDK asset URL
        let bootstrapScriptUrl = bootstrapScriptAsset.s3ObjectUrl;

        // If external assets bucket is provided, use it for bootstrap script
        if (props.assetsBucketName && props.assetsBucketPrefix) {
            // Always use the standard path format with direct context values plus scripts/windows path
            // Ensure there's a trailing slash in the prefix
            const formattedPrefix = props.assetsBucketPrefix.endsWith('/')
                ? props.assetsBucketPrefix
                : `${props.assetsBucketPrefix}/`;
            bootstrapScriptUrl = `s3://${props.assetsBucketName}/${formattedPrefix}scripts/windows/bootstrap.ps1`;
            console.log(`Using workshop assets for bootstrap script: ${bootstrapScriptUrl}`);
        }

        // Create script parameters
        const scriptParams = {
            bootstrapScriptS3Url: bootstrapScriptUrl,
            cloudHsmClusterId: props.cloudHsmClusterId,
            region: this.region || cdk.Stack.of(this).region,
            // Map of script names to their URLs
            scriptS3Urls: Object.fromEntries(
                additionalScripts.map((script, idx) => {
                    // For additional scripts, we could also use the external bucket if specified
                    if (props.assetsBucketName && props.assetsBucketPrefix) {
                        // Always use the standard path format with direct context values
                        // Ensure there's a trailing slash in the prefix
                        const formattedPrefix = props.assetsBucketPrefix.endsWith('/')
                            ? props.assetsBucketPrefix
                            : `${props.assetsBucketPrefix}/`;
                        return [script, `s3://${props.assetsBucketName}/${formattedPrefix}scripts/windows/${script}`];
                    }
                    return [script, additionalScriptAssets[idx].s3ObjectUrl];
                }),
            ),
            customerCaCertPath: `/cloudhsm/${props.cloudHsmClusterId}/customer-ca-cert`,
            clusterCertPath: `/cloudhsm/${props.cloudHsmClusterId}/cluster-cert`,
        };

        // Add debug output to see all script URLs
        new cdk.CfnOutput(this, 'BootstrapScriptUrl', {
            value: scriptParams.bootstrapScriptS3Url,
            description: props.assetsBucketName
                ? 'S3 URL for bootstrap script (using external workshop assets bucket)'
                : 'S3 URL for bootstrap script (using CDK assets bucket)',
        });

        // Create script content using template interpolation
        scriptContent = `
# Deployment version: ${deploymentVersion}
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$VerbosePreference = "Continue"

Start-Transcript -Path "C:\\CloudHSM\\userdata-transcript.log" -Append
New-Item -Path "C:\\CloudHSM" -ItemType Directory -Force -ErrorAction SilentlyContinue

function Get-MetadataToken {
    try {
        $tokenHeaders = @{"X-aws-ec2-metadata-token-ttl-seconds" = "300"}
        $token = Invoke-RestMethod -Headers $tokenHeaders -Method PUT -Uri "http://169.254.169.254/latest/api/token"
        return $token
    } catch {
        Write-Host "Error obtaining IMDSv2 token"
        return $null
    }
}

function Get-Metadata {
    param($Path, $Token)
    try {
        if (-not $Token) {
            $Token = Get-MetadataToken
        }
        $metadataHeaders = @{"X-aws-ec2-metadata-token" = $Token}
        $result = Invoke-RestMethod -Headers $metadataHeaders -Method GET -Uri "http://169.254.169.254/latest/meta-data/$Path"
        return $result
    } catch {
        Write-Host "Error accessing metadata: $Path"
        return $null
    }
}

function Initialize-AWS {
    try {
        $token = Get-MetadataToken
        $roleName = Get-Metadata -Path "iam/security-credentials/" -Token $token
        $credentials = Get-Metadata -Path "iam/security-credentials/$roleName" -Token $token
        $region = Get-Metadata -Path "placement/region" -Token $token
        $instanceId = Get-Metadata -Path "instance-id" -Token $token

        # Import AWS PowerShell modules - try both module names as they vary by installation
        try {
            if (Get-Module -ListAvailable -Name AWSPowerShell) {
                Import-Module AWSPowerShell -ErrorAction Stop
                Write-Host "Imported AWSPowerShell module"
            }
            elseif (Get-Module -ListAvailable -Name AWSPowerShell.NetCore) {
                Import-Module AWSPowerShell.NetCore -ErrorAction Stop
                Write-Host "Imported AWSPowerShell.NetCore module"
            }
            else {
                Write-Host "No AWS PowerShell module found - AWS cmdlets may not be available"
            }

            # Set credentials in PowerShell session
            Set-AWSCredential -AccessKey $credentials.AccessKeyId -SecretKey $credentials.SecretAccessKey -SessionToken $credentials.Token -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Error importing AWS PowerShell module: $_"
        }

        # Always set environment variables as fallback
        $env:AWS_ACCESS_KEY_ID = $credentials.AccessKeyId
        $env:AWS_SECRET_ACCESS_KEY = $credentials.SecretAccessKey
        $env:AWS_SESSION_TOKEN = $credentials.Token
        $env:AWS_DEFAULT_REGION = $region
        $env:AWS_REGION = $region

        return @{
            Success = $true
            Region = $region
            InstanceId = $instanceId
            Role = $roleName
        }
    } catch {
        return @{
            Success = $false
            Region = "${scriptParams.region}"
            Error = $_.Exception.Message
        }
    }
}

# Function definitions removed - VPC endpoint waiting is now handled by the custom resource

function Download-S3File {
    param(
        [Parameter(Mandatory=$true)][string]$Url,
        [Parameter(Mandatory=$true)][string]$OutputPath,
        [Parameter(Mandatory=$false)][string]$Region,
        [Parameter(Mandatory=$false)][int]$MaxRetries = 3
    )

    # Parse the URL to get bucket and key
    try {
        if ($Url -like "s3://*") {
            # Parse s3:// URL format
            $uri = [System.Uri]$Url
            $bucketName = $uri.Host
            $key = $uri.AbsolutePath.TrimStart('/')
            Write-Host "Parsed S3 URL - Bucket: $bucketName, Key: $key"
        }
        else {
            throw "URL is not in s3:// format: $Url"
        }
    }
    catch {
        Write-Host "Error parsing S3 URL: $_"
        return $false
    }

    # Try to download using AWS PowerShell cmdlets
    $retryCount = 0
    $success = $false

    while (-not $success -and $retryCount -lt $MaxRetries) {
        $retryCount++

        try {
            Write-Host "Downloading S3 object (attempt $retryCount)..."
            Read-S3Object -BucketName $bucketName -Key $key -File $OutputPath -Region $Region

            # Fix the Test-Path syntax - separate into two conditions
            if (Test-Path $OutputPath) {
                $fileInfo = Get-Item $OutputPath
                if ($fileInfo.Length -gt 0) {
                    $success = $true
                    Write-Host "Successfully downloaded S3 object"
                    return $true
                }
                else {
                    Write-Host "Downloaded file exists but is empty"
                }
            }
            else {
                Write-Host "Downloaded file is missing"
            }
        }
        catch {
            Write-Host "Download attempt $retryCount failed: $_"

            if ($retryCount -lt $MaxRetries) {
                $sleepTime = 2 * $retryCount
                Write-Host "Retrying in $sleepTime seconds..."
                Start-Sleep -Seconds $sleepTime
            }
        }
    }

    Write-Host "Failed to download S3 object after $MaxRetries attempts"
    return $false
}

Write-Host "Initializing AWS credentials using IMDSv2"
$awsInfo = Initialize-AWS
$region = $awsInfo.Region
Write-Host "AWS initialization complete. Region: $region"

$bootstrapLocalPath = "C:\\CloudHSM\\bootstrap.ps1"
$bootstrapS3Url = "${scriptParams.bootstrapScriptS3Url}"
Write-Host "Downloading bootstrap script from $bootstrapS3Url"

$downloadOk = Download-S3File -Url $bootstrapS3Url -OutputPath $bootstrapLocalPath -Region $region
if (-not $downloadOk) {
    throw "Failed to download bootstrap script after multiple attempts"
}

# Download all additional scripts to a common location
Write-Host "Pre-downloading additional scripts..."
$scriptsDir = "C:\\CloudHSM\\scripts"
New-Item -Path $scriptsDir -ItemType Directory -Force | Out-Null

# Clone the scriptUrls hashtable to avoid modifying the original
$scriptsToDownload = @{
${Object.entries(scriptParams.scriptS3Urls)
    .map(([script, url]) => `    "${script}" = "${url}"`)
    .join('\n')}
}

# Download each script
foreach ($scriptName in $scriptsToDownload.Keys) {
    $scriptUrl = $scriptsToDownload[$scriptName]
    $scriptPath = Join-Path $scriptsDir $scriptName

    Write-Host "Downloading $scriptName from $scriptUrl"
    $scriptOk = Download-S3File -Url $scriptUrl -OutputPath $scriptPath -Region $region

    if (-not $scriptOk) {
        Write-Host "Warning: Failed to pre-download $scriptName" -ForegroundColor Yellow
    } else {
        Write-Host "Successfully downloaded $scriptName" -ForegroundColor Green

        # Also copy to base directory where bootstrap.ps1 might look for it
        Copy-Item -Path $scriptPath -Destination "C:\\CloudHSM\\$scriptName" -Force
    }
}

Write-Host "Executing bootstrap script"
$bootstrapParams = @{
    # Required parameters
    "ClusterId" = "${scriptParams.cloudHsmClusterId}"

    # This parameter name is misleading but required by bootstrap.ps1
    # It expects a directory or URL prefix where scripts can be found
    "BootstrapScriptUrl" = "C:\\CloudHSM\\scripts"

    # Region for AWS operations
    "Region" = "${scriptParams.region}"

    # SSM parameter paths for certificates
    "CustomerCaCertPath" = "${scriptParams.customerCaCertPath}"
    "ClusterCertPath" = "${scriptParams.clusterCertPath}"

    # Pass dictionary of script URLs as fallback
    "ScriptsUrls" = $scriptsToDownload

    # Control settings
    "MaxRetries" = 5
    "Force" = $true
}

Write-Host "Running bootstrap script..."
$startTime = Get-Date

try {
    & $bootstrapLocalPath @bootstrapParams *> "C:\\CloudHSM\\bootstrap-execution.log"
    $exitCode = $LASTEXITCODE

    if ($exitCode -ne 0) {
        Write-Host "Bootstrap failed with exit code $exitCode"
        @{ "status" = "ERROR"; "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); "message" = "Bootstrap failed with exit code: $exitCode" } |
            ConvertTo-Json | Out-File "C:\\CloudHSM\\status.json" -Encoding utf8
        throw "Bootstrap script execution failed with exit code $exitCode"
    } else {
        Write-Host "Bootstrap completed successfully"
        @{ "status" = "SUCCESS"; "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); "message" = "Bootstrap completed successfully" } |
            ConvertTo-Json | Out-File "C:\\CloudHSM\\status.json" -Encoding utf8
    }
} catch {
    Write-Error "Error executing bootstrap script: $_"
    @{ "status" = "ERROR"; "timestamp" = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); "message" = "Bootstrap failed with error: $_" } |
        ConvertTo-Json | Out-File "C:\\CloudHSM\\status.json" -Encoding utf8
    throw
} finally {
    Stop-Transcript
}
`;

        // Normalize newlines to Windows-style CRLF
        scriptContent = scriptContent.replace(/\r?\n/g, '\r\n');

        // For Windows, we need to create properly formatted user data
        // We'll use the standard <powershell> tags with the content directly
        // The CDK will handle the base64 encoding and CloudFormation formatting
        const userData = UserData.custom(`<powershell>${scriptContent}</powershell>`);

        // Ensure the security group allows all outbound traffic
        props.securityGroup.addEgressRule(Peer.anyIpv4(), Port.allTraffic(), 'Allow all outbound traffic');

        // EC2 Instance
        const instance = new Instance(this, 'WinServer', {
            vpc: props.vpc,
            vpcSubnets: {
                subnets: [
                    // Look up the subnet with availability zone
                    cdk.aws_ec2.Subnet.fromSubnetAttributes(this, 'subnet', {
                        subnetId: props.subnetId,
                        availabilityZone: props.vpc.availabilityZones[0],
                    }),
                ],
            },
            instanceType: new InstanceType(props.instanceType),
            machineImage: ami,
            securityGroup: props.securityGroup,
            keyPair: cdk.aws_ec2.KeyPair.fromKeyPairName(this, 'KeyPair', props.keyPairName),
            role: windowsInstanceRole,
            userData,
            requireImdsv2: true, // Enable IMDSv2 requirement
            detailedMonitoring: true, // Enable detailed CloudWatch monitoring
            blockDevices: [
                {
                    deviceName: '/dev/sda1',
                    volume: cdk.aws_ec2.BlockDeviceVolume.ebs(100, {
                        volumeType: cdk.aws_ec2.EbsDeviceVolumeType.GP3,
                        encrypted: true,
                    }),
                },
            ],
        });

        // Add OS tag to properly target instance for SSM QuickSetup configurations
        cdk.Tags.of(instance).add('OS', 'Windows');

        // Security group rules for HTTP/HTTPS moved to CloudHsmNetworkStack

        // Add dependency on the log group to ensure it exists before the instance is created
        instance.node.addDependency(logGroup);

        // Add explicit dependencies on the VPC endpoints to ensure they're available before the instance is created
        // VPC endpoints can take several minutes to fully provision
        instance.node.addDependency(this.ssmEndpoint);
        instance.node.addDependency(this.ec2MessagesEndpoint);
        instance.node.addDependency(this.ssmmessagesEndpoint);
        instance.node.addDependency(this.s3Endpoint);

        // Add dependency on the VPC endpoint waiter to ensure endpoints are fully ready before the instance starts
        // This is crucial as VPC endpoints can take several minutes to fully provision and be DNS resolvable
        instance.node.addDependency(vpcEndpointWaiter);

        // Custom resources have been removed as they're no longer needed
        // SSM QuickSetup handles all the necessary SSM Agent configuration and management

        this.instance = instance;

        new cdk.CfnOutput(this, 'InstanceId', { value: instance.instanceId });
        new cdk.CfnOutput(this, 'PublicDns', {
            value: instance.instancePublicDnsName ?? 'N/A (Instance might be in private subnet)',
        });
        new cdk.CfnOutput(this, 'CloudWatchLogGroup', {
            value: logGroup.logGroupName,
            description: 'CloudWatch Log Group for CloudHSM Workshop',
        });

        // Add outputs for VPC endpoints
        new cdk.CfnOutput(this, 'SSMEndpointId', {
            value: this.ssmEndpoint.vpcEndpointId,
            description: 'SSM VPC Endpoint ID',
            exportName: 'WindowsSSMEndpointId',
        });

        new cdk.CfnOutput(this, 'EC2MessagesEndpointId', {
            value: this.ec2MessagesEndpoint.vpcEndpointId,
            description: 'EC2 Messages VPC Endpoint ID',
            exportName: 'WindowsEC2MessagesEndpointId',
        });

        new cdk.CfnOutput(this, 'SSMMessagesEndpointId', {
            value: this.ssmmessagesEndpoint.vpcEndpointId,
            description: 'SSM Messages VPC Endpoint ID',
            exportName: 'WindowsSSMMessagesEndpointId',
        });

        new cdk.CfnOutput(this, 'S3EndpointId', {
            value: this.s3Endpoint.vpcEndpointId,
            description: 'S3 Gateway VPC Endpoint ID',
            exportName: 'WindowsS3EndpointId',
        });
        // Output removed as SSM Default Management Role is now managed by QuickSetup
    }
}
