# VPC Endpoint Waiter

This custom resource provides a waiter mechanism for VPC endpoints to become fully available and DNS-resolvable.

## Purpose

VPC Endpoints can take several minutes to fully provision and for their DNS entries to be resolvable. This can cause issues when deploying resources that depend on these endpoints being fully operational, such as EC2 instances in private subnets that need to communicate with AWS services via VPC endpoints.

This custom resource checks:
1. If all specified VPC endpoints are in the 'available' state
2. If the DNS names for SSM, EC2Messages, and SSMMessages endpoints resolve to IP addresses
3. If TCP connections can be established to these endpoints

## Usage

This custom resource can be used in CloudFormation to wait for VPC endpoints to be fully ready before proceeding with dependent resources.

### Required Parameters

- `EndpointIds`: A list of VPC endpoint IDs to wait for
- `Region`: The AWS region where the endpoints are deployed

### Example

```typescript
import * as cdk from 'aws-cdk-lib';
import { CustomResource } from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { Provider } from 'aws-cdk-lib/custom-resources';

// Create a Lambda function for the custom resource
const vpcEndpointWaiterLambda = new lambda.Function(this, 'VpcEndpointWaiterLambda', {
  // ... lambda configuration
});

// Create the custom resource provider
const vpcEndpointWaiterProvider = new Provider(this, 'VpcEndpointWaiterProvider', {
  onEventHandler: vpcEndpointWaiterLambda,
  isCompleteHandler: vpcEndpointWaiterLambda,
  totalTimeout: cdk.Duration.minutes(15), // Adjust as needed
});

// Use the custom resource
const vpcEndpointWaiter = new CustomResource(this, 'VpcEndpointWaiter', {
  serviceToken: vpcEndpointWaiterProvider.serviceToken,
  properties: {
    EndpointIds: [ssmEndpoint.vpcEndpointId, ec2MessagesEndpoint.vpcEndpointId, ssmmessagesEndpoint.vpcEndpointId],
    Region: 'eu-west-1'
  }
});

// Make other resources depend on the waiter
yourEC2Instance.node.addDependency(vpcEndpointWaiter);
```

## Implementation Details

The custom resource lambda function performs the following steps:

1. Checks if all VPC endpoints specified in `EndpointIds` are in the "available" state using the EC2 API
2. If all endpoints are available, it then tests DNS resolution for the SSM service endpoints
3. If DNS resolution succeeds, it attempts to establish TCP connections to the endpoints on port 443
4. Only when all these checks pass does the custom resource report completion
5. If any checks fail, the custom resource will continue to retry until the CloudFormation timeout is reached

## Required Lambda Permissions

The Lambda function executing this custom resource requires the following permissions:
- `ec2:DescribeVpcEndpoints`
- Network access to perform DNS resolution and TCP connections
