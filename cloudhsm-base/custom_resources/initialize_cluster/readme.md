# CloudHSM Cluster Initialization Custom Resource

A AWS CDK Custom Resource that handles the initialization of AWS CloudHSM clusters, including certificate generation, signing, and cluster initialization process monitoring.

## Overview

This Custom Resource manages the complete initialization process of a CloudHSM cluster:

- Generates RSA keys and self-signed certificates
- Signs cluster CSR (Certificate Signing Request)
- Initializes the cluster with signed certificates
- Monitors initialization progress
- Stores certificates and keys in AWS Secrets Manager and Parameter Store

## Architecture

```plaintext
Initialize Cluster Flow
├── Certificate Generation
│   ├── RSA Key Generation
│   ├── Self-signed Certificate
│   └── CSR Signing
├── AWS Services Integration
│   ├── Secrets Manager (RSA Key)
│   ├── Parameter Store (Certificate)
│   └── CloudHSM (Cluster Init)
└── State Management
    ├── Initialization Monitoring
    └── Completion Verification
```

## CDK Usage

### TypeScript Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

const initializeCluster = new cr.CustomResource(this, 'InitializeCluster', {
  serviceToken: initializeClusterFunction.functionArn,
  properties: {
    ClusterId: cluster.getAttString('ClusterId'),
    RSASecret: rsaSecret.secretArn,
    SelfSignedCert: '/cloudhsm/cert'
  }
});
```

## Input Properties

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| ClusterId | String | Yes | ID of the CloudHSM cluster to initialize |
| RSASecret | String | Yes | Secrets Manager ARN for storing RSA key |
| SelfSignedCert | String | Yes | SSM Parameter name for certificate |

## Output Attributes

| Attribute | Method | Description |
|-----------|--------|-------------|
| ClusterId | `getAttString('ClusterId')` | The initialized cluster ID |
| ClusterState | `getAttString('ClusterState')` | Current cluster state |
| ClusterCertificate | `getAttString('ClusterCertificate')` | Cluster certificate |

## Docker Build

The Custom Resource uses a Docker container for Lambda deployment:

```bash
# Build for x86_64
docker build -t cloudhsm-init-x86_64 .

# Build for ARM64
docker build --platform linux/arm64 -t cloudhsm-init-arm64 .
```

## Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudhsmv2:DescribeClusters",
        "cloudhsmv2:InitializeCluster",
        "secretsmanager:PutSecretValue",
        "ssm:PutParameter"
      ],
      "Resource": "*"
    }
  ]
}
```

## Certificate Configuration

The self-signed certificate is generated with:
- 2048-bit RSA key
- 365-day validity
- Basic Constraints (CA:TRUE)
- SHA256 signing algorithm

## State Management

The initialization process monitors these states:
- UNINITIALIZED
- INITIALIZE_IN_PROGRESS
- INITIALIZED
- ACTIVE
- DEGRADED

## Limitations

- One initialization per cluster
- Cannot modify after initialization
- Certificate validity period fixed
- No automatic certificate rotation

## Dependencies

- boto3
- cryptography
- Python 3.13
- AWS Lambda container image
- https://www.freecodecamp.org/news/escaping-lambda-function-hell-using-docker-40b187ec1e48/
