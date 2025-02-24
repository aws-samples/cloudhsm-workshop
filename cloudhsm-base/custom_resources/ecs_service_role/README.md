# ECS Service Role Custom Resource

A AWS CDK Custom Resource that manages the creation and lifecycle of the AWS ECS service-linked role.

## Overview

This Custom Resource ensures that the AWS ECS service-linked role (`AWSServiceRoleForECS`) exists in your account. This role is required for ECS services to interact with other AWS services on your behalf.

## CDK Usage

### TypeScript Example

```typescript
import * as cdk from 'aws-cdk-lib';
import * as cr from 'aws-cdk-lib/custom-resources';

const ecsServiceRole = new cr.CustomResource(this, 'EcsServiceRole', {
  serviceToken: ecsServiceRoleFunction.functionArn,
  properties: {
    // No additional properties required
  }
});
```
