# CloudHSM Cluster Activation Custom Resource

A AWS CDK Custom Resource for automating the activation of AWS CloudHSM clusters and initial user setup via AWS Systems Manager Run Command.

## Overview

This Custom Resource automates the following tasks:
- Installs the CloudHSM client on a target EC2 instance
- Configures the client with cluster certificates
- Activates the CloudHSM cluster
- Creates initial Crypto Officer (CO) and Crypto User (CU) accounts

## Architecture

The solution consists of two main components:

1. **Lambda Function (`lambda_function.py`)**
   - Handles Custom Resource lifecycle events (Create/Update/Delete)
   - Executes and monitors SSM Run Command
   - Provides structured logging
   - Implements retry logic and error handling

2. **Activation Script (`activate_cluster.sh`)**
   - Performs the actual cluster activation steps
   - Handles different OS distributions (Ubuntu, Amazon Linux)
   - Implements robust error handling and logging
   - Manages CloudHSM client installation and configuration

## Prerequisites

- An EC2 instance with AWS Systems Manager agent installed
- IAM permissions for SSM Run Command execution
- AWS Secrets Manager secrets containing CO and CU credentials
- SSM Parameter Store parameter containing the cluster's certificate
- CloudHSM cluster deployed and HSM instances available

## Resource Properties

| Property            | Type   | Description                                       |
| ------------------- | ------ | ------------------------------------------------- |
| InstanceId          | string | ID of the EC2 instance to run the activation      |
| COSecret            | string | Secret name containing Crypto Officer credentials |
| CUSecret            | string | Secret name containing Crypto User credentials    |
| ScriptAssetURL      | string | S3 URL to the activation script                   |
| SelfSignedParamName | string | SSM parameter name containing cluster certificate |
| HSMIpAddress        | string | IP address of the HSM instance                    |
| LogGroupName        | string | CloudWatch Log Group for command output           |
| ClusterId           | string | ID of the CloudHSM cluster                        |

## Usage Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

const activateCluster = new cr.AwsCustomResource(this, 'ActivateCluster', {
  onCreate: {
    service: 'CloudHSM',
    action: 'activateCluster',
    parameters: {
      InstanceId: ec2Instance.instanceId,
      COSecret: coSecret.secretName,
      CUSecret: cuSecret.secretName,
      ScriptAssetURL: scriptAsset.s3Url,
      SelfSignedParamName: certParam.parameterName,
      HSMIpAddress: hsmInstance.ipAddress,
      LogGroupName: logGroup.logGroupName,
      ClusterId: cluster.clusterId
    },
    physicalResourceId: cr.PhysicalResourceId.of('CloudHSMActivation')
  }
});
```

## Error Handling

The Custom Resource implements comprehensive error handling:

- Validates all required properties
- Retries SSM command execution with backoff
- Monitors command execution status
- Provides detailed error messages in CloudWatch Logs
- Implements proper Custom Resource response handling

## Logging

Both components provide structured JSON logging:
- Lambda function logs to CloudWatch Logs
- Activation script logs to SSM Run Command output
- Includes timestamps, log levels, and contextual information

## Security Considerations

- Credentials are securely retrieved from AWS Secrets Manager
- Temporary working directories are used and cleaned up
- Secure error handling prevents credential exposure
- Uses AWS Systems Manager for secure command execution

## Limitations

- Only supports Ubuntu and Amazon Linux distributions
- Requires target instance to have AWS Systems Manager agent
- Instance must have necessary IAM permissions
- Network access to CloudHSM endpoints required
