# Windows Systems Manager Default Host Management Configuration

This document explains the approach used for managing Windows instances in the CloudHSM workshop using AWS Systems Manager's Default Host Management Configuration (DHMC).

## Overview

The Windows Systems Manager QuickSetup stack (`WindowsSystemsManagerQuickSetupStack`) replaces the previous custom approach to default host management. It implements AWS's officially recommended approach to enable Default Host Management Configuration to automatically manage EC2 instances:

1. **SSM Agent Updates** - Ensures SSM agent is kept up to date (14-day schedule)
2. **Inventory Collection** - Enables Fleet Manager inventory gathering (12-hour schedule)
3. **Default EC2 Instance Management** - Enables automatic SSM registration without requiring instance profiles

## Implementation Details

### 1. Default Host Management Configuration

The implementation follows AWS's official CloudFormation pattern for enabling DHMC:

```typescript
// Create the managed instance role for SSM default management
this.managedInstanceRole = new iam.Role(this, 'ManagedInstanceRole', {
  roleName: 'AWSSystemsManagerDefaultEC2InstanceManagementRole', // Exact name required by AWS DHMC
  assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com'),
  managedPolicies: [
    iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedEC2InstanceDefaultPolicy')
  ],
  description: 'Role created by SSM to manage EC2 instances by default'
});
```

An automation document is created that enables the service setting for Default Host Management Configuration:

```typescript
const automationDocument = new ssm.CfnDocument(this, 'AutomationRunbookEnableDefaultSSM', {
  documentType: 'Automation',
  content: {
    // ...document definition...
    mainSteps: [
      // Checks existing service setting
      // Updates the service setting if needed
      // Confirms the service setting was updated
    ]
  }
});

// Create association to run the automation document
new ssm.CfnAssociation(this, 'UpdateDefaultEC2InstanceManagementAssociation', {
  name: automationDocument.ref,
  associationName: 'EnableDefaultEC2InstanceManagement',
  // Run once initially and then monthly to ensure the setting stays configured
  scheduleExpression: 'rate(30 days)'
});
```

### 2. SSM Associations

The implementation creates standard SSM associations for agent updates and inventory collection:

```typescript
// Create SSM association for SSM Agent updates
const ssmAgentUpdateAssociation = new ssm.CfnAssociation(this, 'SSMAgentUpdateAssociation', {
  name: 'AWS-UpdateSSMAgent',
  associationName: `AWS-QuickSetup-SSM-UpdateSSMAgent-${configId}`,
  scheduleExpression: 'rate(14 days)',
  targets: [{
    key: 'InstanceIds',
    values: ['*']
  }]
});

// Create SSM association for inventory collection to enable Fleet Manager
const inventoryCollectionAssociation = new ssm.CfnAssociation(this, 'SystemAssociationForInventoryCollection', {
  name: 'AWS-GatherSoftwareInventory',
  associationName: `AWS-QuickSetup-SSM-CollectInventory-${configId}`,
  scheduleExpression: 'rate(12 hours)',
  parameters: {
    applications: ['Enabled'],
    awsComponents: ['Enabled'],
    networkConfig: ['Enabled'],
    instanceDetailedInformation: ['Enabled'],
    windowsUpdates: ['Enabled'],
    services: ['Enabled'],
    windowsRoles: ['Enabled'],
    customInventory: ['Enabled']
  },
  targets: [{
    key: 'InstanceIds',
    values: ['*']
  }]
});
```

## Instance Configuration Requirements

For Windows instances to be managed by SSM Default Host Management Configuration:

1. **IMDSv2 Required**: Instances must use Instance Metadata Service Version 2 (IMDSv2)
2. **SSM Agent Version**: SSM Agent version 3.2.582.0 or later must be installed
3. **OS Tagging**: Windows instances should be tagged with 'OS:Windows' for easier filtering and management

Example of adding the OS tag in the WindowsServerStack:

```typescript
// Add OS tag to properly target instance for SSM operations
cdk.Tags.of(instance).add('OS', 'Windows');
```

## Benefits of Default Host Management Configuration

The Default Host Management Configuration approach offers several advantages:

1. **Standardization**: Uses AWS-recommended approach with best practices
2. **Fleet Manager Integration**: Enables the SSM Fleet Manager interface for Windows instances
3. **Simplified Management**: No need to manually configure instance profiles for SSM
4. **Inventory Collection**: Automatically collects inventory data for better visibility
5. **Automatic Agent Updates**: Keeps SSM Agent up to date automatically
6. **Secure Access**: Enables Session Manager for secure instance connections
7. **Reduced Custom Code**: Eliminates need for custom Lambda-based implementation

## Deployment

This configuration is created as part of the Windows Systems Manager QuickSetup stack, which is deployed alongside the Windows Server stack. The Default Host Management Configuration will automatically manage Windows instances with the 'OS:Windows' tag without requiring additional instance profiles.
