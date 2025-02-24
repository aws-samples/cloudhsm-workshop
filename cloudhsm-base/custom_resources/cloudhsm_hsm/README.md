# CloudHSM HSM Custom Resource

A AWS CDK Custom Resource that manages individual Hardware Security Modules (HSMs) within AWS CloudHSM clusters.

## Overview

This Custom Resource manages the lifecycle of individual HSMs in a CloudHSM cluster, including:

- HSM creation in specific Availability Zones
- State management and monitoring
- Graceful deletion handling
- Network interface tracking

## CDK Usage

### TypeScript Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

const hsm = new cr.CustomResource(this, 'CloudHsmHsm', {
  serviceToken: hsmFunction.functionArn,
  properties: {
    ClusterId: cluster.getAttString('ClusterId'),
    AvailabilityZones: 'us-east-1a,us-east-1b,us-east-1c'  // Comma-separated list
  }
});

// Access outputs
const hsmId = hsm.getAttString('HsmId');
const eniIp = hsm.getAttString('EniIp');
const availabilityZone = hsm.getAttString('AvailabilityZone');
```

### Python Example

```python
from aws_cdk import (
    CustomResource,
    custom_resources as cr,
)

hsm = CustomResource(self, "CloudHsmHsm",
    service_token=hsm_function.function_arn,
    properties={
        "ClusterId": cluster.get_att_string("ClusterId"),
        "AvailabilityZones": "us-east-1a,us-east-1b,us-east-1c"
    }
)

# Access outputs
hsm_id = hsm.get_att_string("HsmId")
eni_ip = hsm.get_att_string("EniIp")
availability_zone = hsm.get_att_string("AvailabilityZone")
```

## Input Properties

| Property          | Type   | Required | Description                           |
| ----------------- | ------ | -------- | ------------------------------------- |
| ClusterId         | String | Yes      | ID of the CloudHSM cluster            |
| AvailabilityZones | String | Yes      | Comma-separated list of available AZs |

## Output Attributes

| Attribute        | Method                             | Description                               |
| ---------------- | ---------------------------------- | ----------------------------------------- |
| HsmId            | `getAttString('HsmId')`            | The ID of the created HSM                 |
| EniIp            | `getAttString('EniIp')`            | IP address of the HSM's network interface |
| EniIpV6          | `getAttString('EniIpV6')`          | IPv6 address (if applicable)              |
| State            | `getAttString('State')`            | Current state of the HSM                  |
| ClusterState     | `getAttString('ClusterState')`     | State of the parent cluster               |
| AvailabilityZone | `getAttString('AvailabilityZone')` | AZ where HSM is deployed                  |
| SubnetId         | `getAttString('SubnetId')`         | Subnet ID where HSM is deployed           |
| EniId            | `getAttString('EniId')`            | ID of the HSM's network interface         |
| NetworkType      | `getAttString('NetworkType')`      | Network type (IPV4/IPV6)                  |

## HSM States

The Custom Resource handles these HSM states:
- CREATE_IN_PROGRESS
- ACTIVE
- DEGRADED
- DELETE_IN_PROGRESS
- DELETED

## Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudhsmv2:CreateHsm",
        "cloudhsmv2:DeleteHsm",
        "cloudhsmv2:DescribeClusters"
      ],
      "Resource": "*"
    }
  ]
}
```

## Best Practices

1. **Availability Zone Selection**
   - Provide multiple AZs for redundancy
   - HSMs are automatically distributed across AZs
   - Avoid AZ conflicts with existing HSMs

2. **Network Planning**
   - Ensure subnet CIDR ranges don't overlap
   - Plan for both IPv4 and IPv6 if needed
   - Consider ENI limits in subnets

3. **State Management**
   - Monitor HSM state transitions
   - Handle DEGRADED state appropriately
   - Allow sufficient time for creation/deletion

4. **Error Handling**
   - Implement proper error handling in dependent resources
   - Monitor CloudWatch Logs for issues
   - Use structured logging for troubleshooting

## Troubleshooting

Common issues and solutions:

1. **Creation Failures**
   - Verify AZ availability
   - Check subnet capacity
   - Ensure proper IAM permissions

2. **Deletion Issues**
   - Verify HSM state before deletion
   - Check cluster state
   - Monitor deletion progress

3. **Network Problems**
   - Verify security group rules
   - Check subnet routing
   - Validate ENI attachment

## Logging

The Custom Resource uses structured JSON logging with:
- Timestamp
- Log level
- Message
- Module and function names
- Contextual properties
- State transition information
