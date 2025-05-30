#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { CloudhsmBaseStack } from '../lib/cloudhsm-base-stack';
import { CloudhsmLookupStack } from '../lib/cloudhsm-lookup-stack';
import { EcsTestStack } from '../lib/cloudhsm-ecs-stack';
import { CloudHsmNetworkStack } from '../lib/cloudhsm-network-stack';
import { WindowsServerStack } from '../lib/windows-server-stack';
import { WindowsSystemsManagerQuickSetupStack } from '../lib/windows-systems-manager-quicksetup-stack';
import { KeyPair } from 'aws-cdk-lib/aws-ec2';

// Create the CDK app
const app = new cdk.App();

// Extract asset bucket parameters from context
const assetsBucketName = app.node.tryGetContext('assetsBucketName');
let assetsBucketPrefix = app.node.tryGetContext('assetsBucketPrefix') || '';

// Ensure the prefix doesn't have trailing slashes to avoid double slashes
if (assetsBucketPrefix && assetsBucketPrefix.endsWith('/')) {
    assetsBucketPrefix = assetsBucketPrefix.slice(0, -1);
}

// If external assets bucket is specified, log the configuration
if (assetsBucketName) {
    console.log(`Using external assets bucket: ${assetsBucketName}`);

    if (assetsBucketPrefix) {
        console.log(`With assets prefix: ${assetsBucketPrefix}`);
    }

    // These parameters will be available to all stacks through the context
    // No further configuration is needed as these parameters are accessed
    // directly by the stacks via context when needed
}

// Get context values with defaults
const context = {
    expressMode: app.node.tryGetContext('express') === 'true' || false,
    requiredAzs: parseInt(app.node.tryGetContext('requiredAzs') || '2'),
    environment: app.node.tryGetContext('environment') || 'Development',
    project: app.node.tryGetContext('project') || 'CloudHSM-Demo',
    region: app.node.tryGetContext('region') || process.env.CDK_DEFAULT_REGION || 'ap-northeast-1', // Default to AP region if nothing is set
    deployWindowsServer: app.node.tryGetContext('windows') === 'true' || false,
    windowsAmiParameter:
        app.node.tryGetContext('windowsAmi') || '/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base',
    windowsInstanceType: app.node.tryGetContext('windowsInstanceType') || 'c5a.xlarge',
    // Asset bucket parameters that can be passed to override the default CDK asset bucket
    assetsBucketName: app.node.tryGetContext('assetsBucketName'),
    assetsBucketPrefix: app.node.tryGetContext('assetsBucketPrefix'),
    // Key pair name for EC2 instance SSH access
    keyPairName: app.node.tryGetContext('keyPairName'),
    githubUrlPath: app.node.tryGetContext('githubUrlPath') || 'aws-samples/cloudhsm-workshop/refs/heads/main',
};

// Define the environment
const env = {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: context.region,
};

// For production use, we should utilize the get_azs.sh script to determine available AZs
// that are compatible with CloudHSM in the current region
// This is handled in the deploy.sh script which runs this script and passes the result via context
// If not provided through context, use simple defaults as fallback
const availableAZs = app.node
    .tryGetContext('availabilityZones')
    ?.split(',')
    .map((az: string) => az.trim()) || [
    // Default to region-based placeholders if no AZs are provided
    `${env.region}a`,
    `${env.region}b`,
];

console.log(`Using availability zones: ${availableAZs.join(', ')}`);

// Create the CloudhsmNetworkStack
const networkStack = new CloudHsmNetworkStack(app, 'CloudhsmNetworkStack', {
    env,
    region: env.region,
    availabilityZones: availableAZs,
    maxAzs: context.requiredAzs,
});

// Create the CloudhsmBaseStack
const cloudHsmStack = new CloudhsmBaseStack(app, 'CloudhsmBaseStack', {
    env,
    vpc: networkStack.vpc,
    availabilityZones: networkStack.availabilityZonesOutput.value.split(','),
    expressMode: context.expressMode,
});

// Add dependency
cloudHsmStack.addDependency(networkStack);

// Create the EcsTestStack
const ecsTestStack = new EcsTestStack(app, 'EcsTestStack', {
    env,
    vpc: networkStack.vpc,
    clusterSG: cloudHsmStack.clusterSG,
    ec2InstanceSG: cloudHsmStack.ec2InstanceSG,
    clusterIdParam: cloudHsmStack.clusterIdParam,
    selfSignedCert: cloudHsmStack.selfSignedCert,
    cuPassword: cloudHsmStack.cuCredentials,
});

// Add dependency
ecsTestStack.addDependency(cloudHsmStack);

// Import the SsmDefaultManagementStack

// Conditionally create the Windows Server Stack if enabled
if (context.deployWindowsServer) {
    // Create the Windows Systems Manager QuickSetup Stack
    const windowsSystemsManagerQuickSetupStack = new WindowsSystemsManagerQuickSetupStack(
        app,
        'WindowsSystemsManagerQuickSetupStack',
        { env },
    );

    console.log('Windows Server deployment enabled');

    // Get an appropriate private subnet for Windows deployment
    const privateSubnets = networkStack.vpc.selectSubnets({
        subnetType: cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS,
    }).subnets;

    const windowsSubnetId = privateSubnets.length > 0 ? privateSubnets[0].subnetId : undefined;

    if (!windowsSubnetId) {
        throw new Error('No private subnet found for Windows Server deployment');
    }

    // We now use the SsmDefaultManagementStack instead of creating the role directly

    // Create the Windows Server Stack (which creates its own SSM Default Management Role)
    const windowsServerStack = new WindowsServerStack(app, 'WindowsServerStack', {
        env,
        vpc: networkStack.vpc,
        subnetId: windowsSubnetId,
        instanceType: context.windowsInstanceType,
        windowsAmiParameter: context.windowsAmiParameter,
        securityGroup: cloudHsmStack.ec2InstanceSG,
        cloudHsmClusterId: cloudHsmStack.clusterId,
        keyPairName: context.keyPairName,
        assetsBucketName: context.assetsBucketName,
        assetsBucketPrefix: context.assetsBucketPrefix,
        // Pass the VPC endpoints from the network stack to avoid creating duplicate endpoints
        ssmEndpoint: networkStack.ssmEndpoint,
        ec2MessagesEndpoint: networkStack.ec2MessagesEndpoint,
        ssmmessagesEndpoint: networkStack.ssmmessagesEndpoint,
        cloudHSMEndpoint: networkStack.cloudHSMEndpoint,
        s3Endpoint: networkStack.s3Endpoint,
        githubRepositoryUrPath: context.githubUrlPath,
        cuCredentials: cloudHsmStack.cuCredentials,
        coCredentials: cloudHsmStack.coCredentials,
        selfSignedCert: cloudHsmStack.selfSignedCert,
        initializedCluster: cloudHsmStack.selfSignedCert,
        clusterIdParam: cloudHsmStack.clusterIdParam,
        endpointSecurityGroup: networkStack.endpointSecurityGroup,
    });

    // Add dependencies - ensure Windows Stack depends on CloudHSM and QuickSetup
    windowsServerStack.addDependency(cloudHsmStack);
    windowsServerStack.addDependency(windowsSystemsManagerQuickSetupStack);

    // Add Windows stack-specific tags
    cdk.Tags.of(windowsServerStack).add('Stack', 'WindowsServer', {
        includeResourceTypes: ['*'],
    });
}

// Add tags to all stacks
const tags = {
    Environment: context.environment.replace(/[^a-zA-Z0-9_.:/=+\-@\s]/g, ''),
    Project: context.project.replace(/[^a-zA-Z0-9_.:/=+\-@\s]/g, ''),
    WindowsEnabled: context.deployWindowsServer.toString(),
};

// Add stack-specific tags
cdk.Tags.of(networkStack).add('Stack', 'Network', {
    includeResourceTypes: ['*'],
});
cdk.Tags.of(cloudHsmStack).add('Stack', 'CloudHSM', {
    includeResourceTypes: ['*'],
});
cdk.Tags.of(ecsTestStack).add('Stack', 'ECS', {
    includeResourceTypes: ['*'],
});

// Add common tags to all stacks
for (const [key, value] of Object.entries(tags)) {
    cdk.Tags.of(app).add(key, value);
}

// Add description to stacks - sanitize the mode text
const mode = context.expressMode ? 'Express' : 'Standard';
const description = `CloudHSM-Demo-Stack-${mode}-Mode`;
cdk.Tags.of(app).add('Description', description);
