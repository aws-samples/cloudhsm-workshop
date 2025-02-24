# CloudHSM Available AZs Finder

A AWS Lambda-based Custom Resource that finds Availability Zones (AZs) that simultaneously support CloudHSM, EC2, and ECS services.

## Overview

This Custom Resource helps determine which AZs in a given AWS region support all required services (CloudHSM, EC2, and ECS). It's particularly useful when deploying CloudHSM clusters that need to integrate with EC2 and ECS workloads.

## Features

- Finds AZs that support all required services
- Validates input parameters
- Provides structured JSON logging
- Handles AWS API errors gracefully
- Returns a specified number of available AZs

## Usage

### CloudFormation Template Example

```yaml
Resources:
  AZLookup:
    Type: Custom::CloudHsmAZLookup
    Properties:
      ServiceToken: !GetAtt CloudHsmAZLookupFunction.Arn
      Region: !Ref AWS::Region
      RequiredNumberOfAZs: 2
```

### Input Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| Region | String | Yes | AWS Region to check for AZ availability |
| RequiredNumberOfAZs | Integer | Yes | Number of AZs required (must be > 0) |

### Output Properties

| Property | Description |
|----------|-------------|
| AvailableAZs | Comma-separated list of available AZs |
| NumberOfAZs | Total number of AZs returned |

## Error Handling

The function handles several error conditions:

- `InsufficientAZsError`: When there aren't enough AZs available
- `ServiceNotAvailableError`: When CloudHSM service is not available in the region
- `ValueError`: When input validation fails
- AWS API errors (BotoCoreError, ClientError)

## Logging

The function uses structured JSON logging with the following fields:

- timestamp
- level
- message
- module
- function
- Additional contextual properties

## Requirements

- Python 3.x
- boto3
- AWS Lambda execution role with permissions for:
  - ec2:DescribeVpcEndpointServices
  - ec2:DescribeAvailabilityZones
  - ecs:* (for future ECS-specific checks)
