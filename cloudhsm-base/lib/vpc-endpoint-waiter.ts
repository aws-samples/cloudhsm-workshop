import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as path from 'path';
import { Construct } from 'constructs';
import { Provider } from 'aws-cdk-lib/custom-resources';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

/**
 * Properties for the VPC Endpoint Waiter
 */
export interface VpcEndpointWaiterProps {
  /**
   * The VPC Endpoints to wait for
   */
  readonly endpoints: ec2.IVpcEndpoint[];

  /**
   * The VPC where the endpoints are located
   * This is needed for deploying the Lambda function
   */
  readonly vpc: ec2.IVpc;

  /**
   * The AWS Region where the endpoints are located
   */
  readonly region: string;

  /**
   * Custom timeout for waiting for endpoints to become available (in seconds)
   * @default 900 seconds (15 minutes)
   */
  readonly timeoutSeconds?: number;
}

/**
 * Custom resource that waits for VPC Endpoints to become fully available and DNS-resolvable.
 *
 * VPC Endpoints can take several minutes to fully provision and for their DNS entries to propagate.
 * This resource ensures that endpoints are fully operational before allowing dependent resources to proceed.
 */
export class VpcEndpointWaiter extends Construct {
  /**
   * The custom resource that performs the waiting
   */
  public readonly customResource: cdk.CustomResource;

  /**
   * The underlying Lambda function that checks endpoint status
   */
  public readonly function: lambda.Function;

  constructor(scope: Construct, id: string, props: VpcEndpointWaiterProps) {
    super(scope, id);

    if (props.endpoints.length === 0) {
      throw new Error('At least one VPC Endpoint must be provided');
    }

    // Create Lambda function for the custom resource
    // For the Lambda function to properly verify DNS resolution and TCP connectivity
    // to VPC endpoints, it needs to be deployed in the same VPC as the endpoints
    const vpc = props.vpc;

    this.function = new lambda.Function(this, 'VpcEndpointWaiterFunction', {
      runtime: lambda.Runtime.PYTHON_3_9,
      handler: 'lambda_function.handler',
      code: lambda.Code.fromAsset(path.join(
        __dirname, '..', 'custom_resources', 'vpc_endpoint_waiter'
      )),
      timeout: cdk.Duration.seconds(30), // Each invocation timeout
      memorySize: 128,
      description: 'Custom Resource to wait for VPC endpoints to be fully available and DNS-resolvable',
      vpc, // Deploy Lambda in the same VPC as the endpoints
      vpcSubnets: {
        subnetType: cdk.aws_ec2.SubnetType.PRIVATE_WITH_EGRESS // Use private subnets with NAT
      },
      allowPublicSubnet: false,
      securityGroups: [
        new cdk.aws_ec2.SecurityGroup(this, 'LambdaSecurityGroup', {
          vpc,
          description: 'Security group for VPC Endpoint Waiter Lambda',
          allowAllOutbound: true
        })
      ]
    });

    // Add required permissions
    this.function.addToRolePolicy(new iam.PolicyStatement({
      actions: ['ec2:DescribeVpcEndpoints'],
      resources: ['*'], // Scope down to specific endpoints if needed
      effect: iam.Effect.ALLOW,
    }));

    // Create a custom resource provider
    const provider = new Provider(this, 'VpcEndpointWaiterProvider', {
      onEventHandler: this.function,
      isCompleteHandler: this.function, // Same Lambda handles isComplete
      totalTimeout: cdk.Duration.seconds(props.timeoutSeconds || 900), // Default 15 minutes
      logRetention: cdk.aws_logs.RetentionDays.ONE_WEEK, // Keep logs for a week
    });

    // Create the custom resource
    this.customResource = new cdk.CustomResource(this, 'Resource', {
      serviceToken: provider.serviceToken,
      resourceType: 'Custom::VpcEndpointWaiter',
      properties: {
        EndpointIds: props.endpoints.map(endpoint => endpoint.vpcEndpointId),
        Region: props.region,
        // Add a timestamp to ensure the resource is re-evaluated on each deployment
        Timestamp: new Date().toISOString(),
      },
    });

    // Add explicit dependencies on all the endpoints
    props.endpoints.forEach(endpoint => {
      this.customResource.node.addDependency(endpoint);
    });
  }
}
