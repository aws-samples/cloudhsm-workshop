# CloudHSM Cluster Ready Gate Custom Resource

A AWS CDK Custom Resource that acts as a gate/waiter for CloudHSM clusters to reach the ACTIVE state before allowing dependent resources to proceed.

## Overview

This Custom Resource provides a way to ensure CloudHSM clusters are fully ACTIVE before proceeding with dependent operations, such as:

- HSM creation
- Cluster initialization
- Client configuration
- Application deployment

## CDK Usage

### TypeScript Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

const clusterGate = new cr.CustomResource(this, 'CloudHsmClusterGate', {
  serviceToken: clusterGateFunction.functionArn,
  properties: {
    ClusterId: cluster.getAttString('ClusterId')
  }
});

// Access outputs
const clusterState = clusterGate.getAttString('State');
const securityGroup = clusterGate.getAttString('SecurityGroup');
const vpcId = clusterGate.getAttString('VpcId');
```

## Input Properties

| Property  | Type   | Required | Description                           |
| --------- | ------ | -------- | ------------------------------------- |
| ClusterId | String | Yes      | ID of the CloudHSM cluster to monitor |

## Output Attributes

| Attribute     | Method                          | Description                      |
| ------------- | ------------------------------- | -------------------------------- |
| ClusterId     | `getAttString('ClusterId')`     | The ID of the monitored cluster  |
| State         | `getAttString('State')`         | Current state of the cluster     |
| SecurityGroup | `getAttString('SecurityGroup')` | Security group ID                |
| VpcId         | `getAttString('VpcId')`         | VPC ID where cluster is deployed |
| SubnetMapping | `getAttJson('SubnetMapping')`   | Mapping of subnets used          |
| HsmType       | `getAttString('HsmType')`       | Type of HSM instances            |
| NetworkType   | `getAttString('NetworkType')`   | Network type (IPV4/IPV6)         |

## Cluster States

The Custom Resource monitors these cluster states:
- CREATE_IN_PROGRESS
- UNINITIALIZED
- INITIALIZE_IN_PROGRESS
- INITIALIZED
- ACTIVE
- UPDATE_IN_PROGRESS
- MODIFY_IN_PROGRESS
- ROLLBACK_IN_PROGRESS
- DELETE_IN_PROGRESS
- DELETED
- DEGRADED

## Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudhsmv2:DescribeClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

## Best Practices

1. **Dependency Management**
   - Use this gate before creating HSMs
   - Wait for ACTIVE state before initialization
   - Include in dependency chain for applications

2. **Error Handling**
   - Monitor for DEGRADED state
   - Handle transition states appropriately
   - Set appropriate timeouts in CDK

3. **State Transitions**
   - Account for all possible state transitions
   - Handle rollback scenarios
   - Monitor progress through CloudWatch

4. **Resource Cleanup**
   - Gate properly handles cluster deletion
   - Monitors deletion progress
   - Cleans up resources when cluster is gone

## Logging

The Custom Resource uses structured JSON logging with:
- Timestamp
- Log level
- Message
- Module and function names
- Contextual properties
- State transition information

## Usage Tips

1. **Stack Dependencies**
```typescript
// Make other resources depend on the gate
const otherResource = new SomeResource(this, 'Resource', {
  // ... other properties
});
otherResource.node.addDependency(clusterGate);
```

2. **Condition Checking**

```typescript
// Use the gate's outputs for conditions
const isClusterReady = clusterGate.getAttString('State') === 'ACTIVE';
```
