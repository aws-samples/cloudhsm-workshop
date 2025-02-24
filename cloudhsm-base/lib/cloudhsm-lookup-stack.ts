import * as cdk from 'aws-cdk-lib';
import * as custom from 'aws-cdk-lib/custom-resources';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import { Construct } from 'constructs';

export interface CloudhsmLookupStackProps extends cdk.StackProps {
  region: string;
  requiredNumberOfAZs: number;
}

export class CloudhsmLookupStack extends cdk.Stack {
  public readonly availableAZsString: string;
  public availableAZsOutput: cdk.CfnOutput;
  public requiredNumberOfAZsOutput: cdk.CfnOutput;

  private readonly requiredNumberOfAZs: number;

  constructor(scope: Construct, id: string, props: CloudhsmLookupStackProps) {
    super(scope, id, props);

    this.requiredNumberOfAZs = props.requiredNumberOfAZs;

    const azLookupFunction = this.createAZLookupFunction();
    const azLookupProvider = this.createAZLookupProvider(azLookupFunction);
    const azLookup = this.createAZLookupResource(azLookupProvider);

    this.availableAZsString = azLookup.getAttString('AvailableAZs');

    this.createOutputs();
  }

  private createAZLookupFunction(): lambda.Function {
    const fn = new lambda.Function(this, 'AZLookupFunction', {
      runtime: lambda.Runtime.PYTHON_3_13, // Using a more stable version
      handler: 'lambda_function.handler',
      code: lambda.Code.fromAsset('./custom_resources/cloudhsm_az_lookup/'),
      timeout: cdk.Duration.minutes(5),
      environment: {
        REGION: this.region,
      },
    });

    fn.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          'ec2:DescribeAvailabilityZones',
          'ec2:DescribeVpcEndpointServices',
        ],
        resources: ['*'],
      }),
    );

    return fn;
  }

  private createAZLookupProvider(
    azLookupFunction: lambda.Function,
  ): custom.Provider {
    return new custom.Provider(this, 'AZLookupProvider', {
      onEventHandler: azLookupFunction,
    });
  }

  private createAZLookupResource(
    azLookupProvider: custom.Provider,
  ): cdk.CustomResource {
    return new cdk.CustomResource(this, 'AZLookup', {
      serviceToken: azLookupProvider.serviceToken,
      properties: {
        Region: this.region,
        RequiredNumberOfAZs: this.requiredNumberOfAZs,
      },
    });
  }

  private createOutputs(): void {
    this.availableAZsOutput = new cdk.CfnOutput(this, 'AvailableAZsOutput', {
      value: this.availableAZsString,
      description: 'Available AZs for CloudHSM',
      exportName: 'CloudHsmAvailableAZs',
    });

    this.requiredNumberOfAZsOutput = new cdk.CfnOutput(
      this,
      'RequiredNumberOfAZsOutput',
      {
        value: this.requiredNumberOfAZs.toString(),
        description: 'Required number of AZs for CloudHSM',
        exportName: 'CloudHsmRequiredNumberOfAZs',
      },
    );
  }
}
