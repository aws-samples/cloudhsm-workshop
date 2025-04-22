# CloudHSM Cluster Custom Resource

A AWS CDK Custom Resource that manages the lifecycle of AWS CloudHSM clusters, including creation, updates, and deletion.

## Overview

This Custom Resource provides a way to manage CloudHSM clusters through CDK, handling the complete lifecycle including:

- Cluster creation with configurable subnet and security group settings
- Graceful deletion with backup cleanup
- State management and completion tracking
- Security group validation

## CDK Usage

### TypeScript Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as cr from 'aws-cdk-lib/custom-resources';

const cloudHsmCluster = new cr.CustomResource(this, 'CloudHsmCluster', {
  serviceToken: cloudHsmFunction.functionArn,
  properties: {
    SubnetIds: vpc.privateSubnets.map(subnet => subnet.subnetId),
    SecurityGroupId: securityGroup.securityGroupId,
    Mode: "FIPS", // Optional: Set to "FIPS" or "NON_FIPS" (defaults to "NON_FIPS" if not specified)
  },
});

// Access outputs
const clusterId = cloudHsmCluster.getAttString('ClusterId');
const clusterState = cloudHsmCluster.getAttString('State');
```

### Python Example

```python
from aws_cdk import (
    CustomResource,
    aws_ec2 as ec2,
    custom_resources as cr,
)

cloud_hsm_cluster = CustomResource(self, "CloudHsmCluster",
    service_token=cloud_hsm_function.function_arn,
    properties={
        "SubnetIds": [subnet.subnet_id for subnet in vpc.private_subnets],
        "SecurityGroupId": security_group.security_group_id,
        "Mode": "FIPS"  # Optional: Set to "FIPS" or "NON_FIPS" (defaults to "NON_FIPS" if not specified)
    }
)

# Access outputs
cluster_id = cloud_hsm_cluster.get_att_string("ClusterId")
cluster_state = cloud_hsm_cluster.get_att_string("State")
```

## Input Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| SubnetIds | List[String] | Yes | List of subnet IDs where the cluster will be deployed |
| SecurityGroupId | String | No | Security group ID for the cluster |
| Mode | String | No | Cluster mode, can be "FIPS" or "NON_FIPS". Defaults to "NON_FIPS" |

## Output Attributes

| Attribute | Method | Description |
|-----------|--------|-------------|
| ClusterId | `getAttString('ClusterId')` | The ID of the created CloudHSM cluster |
| SecurityGroupId | `getAttString('SecurityGroupId')` | The security group associated with the cluster |
| State | `getAttString('State')` | Current state of the cluster |
| SubnetMapping | `getAttJson('SubnetMapping')` | Mapping of subnets used by the cluster |
| VpcId | `getAttString('VpcId')` | VPC ID where the cluster is deployed |

## Configuration Details

### Cluster Configuration
- Instance Type: hsm2m.medium
- Mode: NON_FIPS (default, can be set to FIPS using the Mode property)
- Backup Retention: 7 days

### Security Considerations
- Security groups cannot be updated after cluster creation
- Multi-AZ deployment is supported through subnet selection
- Ensure the security group allows necessary HSM communication ports

## Required Permissions

The Lambda function requires these IAM permissions:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudhsmv2:CreateCluster",
        "cloudhsmv2:DeleteCluster",
        "cloudhsmv2:DescribeClusters",
        "cloudhsmv2:DescribeBackups",
        "cloudhsmv2:DeleteBackup"
      ],
      "Resource": "*"
    }
  ]
}
```

## Error Handling

The Custom Resource handles several scenarios:
- Invalid security group updates
- Cluster not found conditions
- Failed state transitions
- Backup deletion failures

## Best Practices

1. **VPC Configuration**
   - Use private subnets for enhanced security
   - Configure appropriate route tables and NACLs

2. **Security Groups**
   - Define security group rules before cluster creation
   - Cannot be modified after cluster creation

3. **Backup Management**
   - Backups are automatically managed with 7-day retention
   - Cleaned up during cluster deletion

4. **Monitoring**
   - Monitor cluster state transitions through CloudWatch Logs
   - Use structured logging for better observability

## Troubleshooting

Common issues and solutions:
- If cluster creation fails, check subnet configurations
- For security group issues, verify all required ports are open
- During deletion, ensure all HSMs are removed first
