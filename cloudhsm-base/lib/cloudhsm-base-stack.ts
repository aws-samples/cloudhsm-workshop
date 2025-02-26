import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as custom from 'aws-cdk-lib/custom-resources';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import { Asset } from 'aws-cdk-lib/aws-s3-assets';
import * as path from 'path';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as elbv2 from 'aws-cdk-lib/aws-elasticloadbalancingv2';
import * as targets from 'aws-cdk-lib/aws-elasticloadbalancingv2-targets';
import cluster from 'cluster';

// Constants
const EC2_INSTANCE_TYPE = 't3.nano';
const LAMBDA_TIMEOUT = cdk.Duration.seconds(300);
const LAMBDA_PYTHON_RUNTIME = lambda.Runtime.PYTHON_3_13;

interface CloudHsmReadyGateResult {
  readyGate: cdk.CustomResource;
  secondNode?: cdk.CustomResource;
}

export interface CloudhsmBaseStackProps extends cdk.StackProps {
  vpc: ec2.IVpc;
  availabilityZones: string[];
  expressMode: boolean;
}

export class CloudhsmBaseStack extends cdk.Stack {
  // Public and protected members
  public readonly clusterSG: ec2.ISecurityGroup;
  public readonly ec2InstanceSG: ec2.SecurityGroup;
  public cuPassword: secretsmanager.ISecret;
  protected readonly _availabilityZones: string[];
  public readonly clusterId: string;

  // Private readonly members for resources
  private readonly vpc: ec2.IVpc;
  private readonly expressMode: boolean;
  private readonly cloudHsmNodeProvider: custom.Provider;
  private readonly cloudHsmClusterProvider: custom.Provider;
  private readonly clusterReadyProvider: custom.Provider;
  private readonly activateClusterProvider: custom.Provider;
  private readonly initializeClusterProvider: custom.Provider;
  private readonly clusterReadyGate: cdk.CustomResource; // In class members

  private readonly adminInstance: ec2.Instance;
  private readonly clientInstance: ec2.Instance;
  public readonly clusterIdParam: ssm.StringParameter;
  public readonly selfSignedCert: ssm.StringParameter;
  private readonly rsaKey: secretsmanager.Secret;

  constructor(scope: Construct, id: string, props: CloudhsmBaseStackProps) {
    super(scope, id, props);

    // 1. Initialize basic properties
    this.vpc = props.vpc;
    this.expressMode = props.expressMode;
    this._availabilityZones = props.availabilityZones;

    // 2. Create network resources
    const ec2InstanceSecurityGroup = this.createNetworkResources();

    this.ec2InstanceSG = ec2InstanceSecurityGroup;

    // 3. Initialize providers
    this.cloudHsmNodeProvider = this.createCloudHsmNodeProvider();
    this.cloudHsmClusterProvider = this.createCloudHsmClusterProvider();
    this.clusterReadyProvider = this.createClusterReadyProvider();
    this.activateClusterProvider = this.createActivateClusterProvider();
    this.initializeClusterProvider = this.createInitializeClusterProvider();

    // 4. Create roles
    const adminInstanceRole = this.createAdminInstanceRole();
    const clientInstanceRole = this.createClientInstanceRole();

    const privateSubnets = this.getOnePrivateSubnetPerAZ();

    // 5. Create admin instance
    this.adminInstance = this.createAdminInstance(
      this.vpc,
      ec2InstanceSecurityGroup,
      EC2_INSTANCE_TYPE,
      adminInstanceRole,
    );

    // 6. Create cluster and get security group
    const clusterCreationResult = this.createCloudHsmCluster(
      this.adminInstance,
      privateSubnets,
    );
    this.clusterIdParam = clusterCreationResult.clusterIdParam;
    this.clusterSG = clusterCreationResult.clusterSG;
    this.clusterId = clusterCreationResult.clusterId;

    // Ensure the admin instance has cluster security group
    this.adminInstance.addSecurityGroup(this.clusterSG);

    // 7. Create primary HSM node
    const { ip: primaryNodeIp, node: primaryNode } = this.createCloudHsmNode(
      'PrimaryHsmNode',
      {
        ClusterId: this.clusterId,
        AvailabilityZones: this._availabilityZones.join(','),
      },
    );

    // 8. Initialize cluster
    const { rsaKey, selfSignedCert, initializedCluster } =
      this.initializeCluster(this.clusterId);

    initializedCluster.node.addDependency(primaryNode);

    this.rsaKey = rsaKey;
    this.selfSignedCert = selfSignedCert;

    // 9. Activate cluster
    const { coPassword, cuPassword, activatedClusterTarget } =
      this.activateCluster(this.adminInstance, this.clusterId, primaryNodeIp);
    this.cuPassword = cuPassword;

    activatedClusterTarget.node.addDependency(
      this.initializeClusterProvider.onEventHandler,
    );
    activatedClusterTarget.node.addDependency(this.adminInstance);
    activatedClusterTarget.node.addDependency(initializedCluster);

    // 10. Create cluster ready gate
    this.clusterReadyGate = this.createCloudHsmReadyGate(this.clusterId);

    this.clusterReadyGate.node.addDependency(activatedClusterTarget);

    if (!this.expressMode) {
      const { ip: secondNodeIp, node: secondNode } = this.createCloudHsmNode(
        'SecondHsmNode',
        {
          ClusterId: this.clusterId,
          AvailabilityZones: this._availabilityZones.reverse().join(', '),
        },
      );
      secondNode.node.addDependency(this.clusterReadyGate);
    }

    // 11. Create client instance
    this.clientInstance = this.createClientInstance(
      this.vpc,
      ec2InstanceSecurityGroup,
      EC2_INSTANCE_TYPE,
      clientInstanceRole,
    );

    this.clientInstance.addSecurityGroup(this.clusterSG);

    this.clientInstance.node.addDependency(this.clusterReadyGate);

    // 12. Create outputs
    this.createOutputs();
  }

  private createNetworkResources(): ec2.SecurityGroup {
    const ec2InstanceSG = new ec2.SecurityGroup(this, 'ec2InstanceSG', {
      vpc: this.vpc,
      description: 'CloudHSM Admin Instance',
      allowAllOutbound: true,
    });

    ec2InstanceSG.addIngressRule(
      ec2.Peer.anyIpv4(),
      ec2.Port.tcp(443),
      'Allow HTTPS Inbound',
    );
    return ec2InstanceSG;
  }

  // Provider creation methods
  private createCloudHsmNodeProvider(): custom.Provider {
    const cloudHsmFunction = new lambda.Function(this, 'cloudHSM2Provider', {
      runtime: LAMBDA_PYTHON_RUNTIME,
      code: lambda.Code.fromAsset('./custom_resources/cloudhsm_hsm/'),
      handler: 'lambda_function.handler',
    });

    this.addCloudHsmPolicies(cloudHsmFunction);

    const isCompleteFunction = new lambda.Function(
      this,
      'cloudHsm2ProviderIsComplete',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/cloudhsm_hsm/'),
        handler: 'lambda_function.isComplete',
      },
    );

    isCompleteFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cloudhsm:DescribeClusters', 'cloudhsm:DeleteHsm'],
        resources: ['*'],
      }),
    );

    return new custom.Provider(this, 'CloudHSM2Provider', {
      onEventHandler: cloudHsmFunction,
      isCompleteHandler: isCompleteFunction,
      queryInterval: cdk.Duration.seconds(15),
    });
  }

  private createCloudHsmClusterProvider(): custom.Provider {
    const cloudHsmClusterFunction = new lambda.Function(
      this,
      'cloudHSMProvider',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/cloudhsm_cluster/'),
        handler: 'lambda_function.handler',
      },
    );

    cloudHsmClusterFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cloudhsm:DescribeClusters',
          'cloudhsm:DescribeBackups',
          'cloudhsm:CreateCluster',
          'cloudhsm:CreateHsm',
          'cloudhsm:RestoreBackup',
          'cloudhsm:CopyBackupToRegion',
          'cloudhsm:InitializeCluster',
          'cloudhsm:ListTags',
          'cloudhsm:TagResource',
          'cloudhsm:UntagResource',
          'cloudhsm:DeleteCluster',
          'cloudhsm:DeleteBackup',
          'cloudhsm:DeleteHsm',
          'ec2:CreateNetworkInterface',
          'ec2:DescribeNetworkInterfaces',
          'ec2:DescribeNetworkInterfaceAttribute',
          'ec2:DescribeVpcEndpointServices',
          'ec2:DetachNetworkInterface',
          'ec2:DeleteNetworkInterface',
          'ec2:CreateSecurityGroup',
          'ec2:AuthorizeSecurityGroupIngress',
          'ec2:AuthorizeSecurityGroupEgress',
          'ec2:RevokeSecurityGroupEgress',
          'ec2:DescribeSecurityGroups',
          'ec2:DeleteSecurityGroup',
          'ec2:CreateTags',
          'ec2:DescribeVpcs',
          'ec2:DescribeSubnets',
          'iam:CreateServiceLinkedRole',
        ],
        resources: ['*'],
      }),
    );

    const cloudHsmClusterIsCompleteFunction = new lambda.Function(
      this,
      'cloudHSMProviderIsComplete',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/cloudhsm_cluster/'),
        handler: 'lambda_function.isComplete',
      },
    );

    cloudHsmClusterIsCompleteFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cloudhsm:DescribeClusters',
          'cloudhsm:DeleteCluster',
          'ec2:DeleteNetworkInterface',
          'ec2:DeleteSecurityGroup',
        ],
        resources: ['*'],
      }),
    );

    const cloudhsmClusterProvider = new custom.Provider(
      this,
      'cloudHSMClusterCR',
      {
        onEventHandler: cloudHsmClusterFunction,
        isCompleteHandler: cloudHsmClusterIsCompleteFunction,
        queryInterval: cdk.Duration.seconds(15),
      },
    );

    return cloudhsmClusterProvider;
  }

  private createClusterReadyProvider(): custom.Provider {
    const clusterReadyFunction = new lambda.Function(
      this,
      'ClusterReadyFunction',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/cluster_ready_gate/'),
        handler: 'lambda_function.handler',
      },
    );

    clusterReadyFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cloudhsm:DescribeClusters'],
        resources: ['*'],
      }),
    );

    const isCompleteFunction = new lambda.Function(
      this,
      'ClusterReadyIsCompleteFunction',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/cluster_ready_gate/'),
        handler: 'lambda_function.isComplete',
      },
    );

    isCompleteFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cloudhsm:DescribeClusters'],
        resources: ['*'],
      }),
    );

    return new custom.Provider(this, 'clusterReadyProviderCR', {
      onEventHandler: clusterReadyFunction,
      isCompleteHandler: isCompleteFunction,
      queryInterval: cdk.Duration.seconds(15),
    });
  }

  private createActivateClusterProvider(): custom.Provider {
    const activateClusterFunction = new lambda.Function(
      this,
      'activateClusterFunction',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/activate_cluster'),
        handler: 'lambda_function.handler',
        architecture: lambda.Architecture.X86_64,
      },
    );

    activateClusterFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ssm:SendCommand', 'ssm:GetCommandInvocation'],
        resources: ['*'],
      }),
    );

    const isCompleteFunction = new lambda.Function(
      this,
      'activateClusterCompleteFunction',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/activate_cluster'),
        handler: 'lambda_function.isComplete',
        architecture: lambda.Architecture.X86_64,
      },
    );

    this.addCloudHsmPolicies(isCompleteFunction);

    isCompleteFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cloudhsm:DescribeClusters'],
        resources: ['*'],
      }),
    );

    isCompleteFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ssm:SendCommand', 'ssm:GetCommandInvocation'],
        resources: ['*'],
      }),
    );

    const activateClusterProvider = new custom.Provider(
      this,
      'activateClusterProvider',
      {
        onEventHandler: activateClusterFunction,
        isCompleteHandler: isCompleteFunction,
        queryInterval: cdk.Duration.seconds(15),
      },
    );

    return activateClusterProvider;
  }

  private createInitializeClusterProvider(): custom.Provider {
    const SSM_PARAMETER_ARN = `arn:aws:ssm:${this.region}:${this.account}:parameter/cloudhsm/workshop/selfsignedcert`;
    const SECRET_ARN = `arn:aws:secretsmanager:${this.region}:${this.account}:secret:/cloudhsm/workshop/*`;

    const functionRole = new iam.Role(this, 'InitializeClusterFunctionRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'service-role/AWSLambdaBasicExecutionRole',
        ),
      ],
      inlinePolicies: {
        InitializeClusterPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'ssm:SendCommand',
                'ssm:GetCommandInvocation',
                'ssm:PutParameter',
                'ssm:GetParameter',
              ],
              resources: [
                SSM_PARAMETER_ARN,
                `arn:aws:ssm:${this.region}:${this.account}:document/*`,
                `arn:aws:ec2:${this.region}:${this.account}:instance/*`,
              ],
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: [
                'secretsmanager:PutSecretValue',
                'secretsmanager:GetSecretValue',
                'secretsmanager:DescribeSecret',
              ],
              resources: [SECRET_ARN],
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['cloudhsm:*'],
              resources: ['*'],
            }),
          ],
        }),
      },
    });

    const initializeClusterFunction = new lambda.DockerImageFunction(
      this,
      'initializeClusterDockerImage',
      {
        code: lambda.DockerImageCode.fromImageAsset(
          './custom_resources/initialize_cluster/',
        ),
        architecture: lambda.Architecture.X86_64,
        timeout: LAMBDA_TIMEOUT,
        role: functionRole,
      },
    );

    const isCompleteFunction = new lambda.Function(
      this,
      'initializeClusterIsCompleteFunction',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/initialize_cluster/'),
        handler: 'complete.isComplete',
        architecture: lambda.Architecture.X86_64,
        role: functionRole,
      },
    );

    return new custom.Provider(this, 'generateKeysProvider', {
      onEventHandler: initializeClusterFunction,
      isCompleteHandler: isCompleteFunction,
      queryInterval: cdk.Duration.seconds(15),
    });
  }

  private createCloudHsmNode(
    id: string,
    properties: Record<string, any>,
  ): {
    ip: string;
    node: cdk.CustomResource;
  } {
    const node = new cdk.CustomResource(this, id, {
      serviceToken: this.cloudHsmNodeProvider.serviceToken,
      properties,
    });

    return {
      ip: cdk.Token.asString(node.getAtt('EniIp')),
      node: node,
    };
  }

  private createCloudHsmCluster(
    adminInstance: ec2.Instance,
    privateSubnets: ec2.ISubnet[],
  ): {
    cluster: cdk.CustomResource;
    clusterId: string;
    clusterSG: ec2.SecurityGroup;
    clusterIdParam: ssm.StringParameter;
  } {
    // Create the cluster
    const cluster = new cdk.CustomResource(this, 'cloudHSMCluster', {
      serviceToken: this.cloudHsmClusterProvider.serviceToken,
      properties: {
        SubnetIds: privateSubnets.map((subnet) => subnet.subnetId),
      },
    });

    // Get the cluster ID from the custom resource
    const clusterId = cluster.getAttString('ClusterId');

    // Create the security group
    const clusterSG = ec2.SecurityGroup.fromSecurityGroupId(
      this,
      'CloudHSMClusterSG',
      cluster.getAttString('SecurityGroupId'),
    );

    clusterSG.node.addDependency(cluster);

    // Create the parameter to store the cluster ID
    const clusterIdParam = new ssm.StringParameter(this, 'clusterIdParam', {
      stringValue: clusterId,
      parameterName: '/cloudhsm/workshop/clusterId',
    });

    // Add dependencies
    clusterIdParam.node.addDependency(cluster);

    // Optional: Validate the security group ID matches what we expect
    new cdk.CfnOutput(this, 'ValidateSecurityGroup', {
      value: cluster.getAttString('SecurityGroupId'),
      description: 'Verify this matches our created security group',
    });

    return {
      cluster,
      clusterId,
      clusterSG: clusterSG as ec2.SecurityGroup,
      clusterIdParam,
    };
  }

  private initializeCluster(clusterId: string): {
    rsaKey: secretsmanager.Secret;
    selfSignedCert: ssm.StringParameter;
    initializedCluster: cdk.CustomResource;
  } {
    // Check if the RSA key already exists
    let rsaKey: secretsmanager.Secret;
    try {
      // First try to create a new secret
      rsaKey = new secretsmanager.Secret(this, 'rsaKey', {
        description:
          'RSA Key used to sign HSM certificates. This key should be stored off-site (and offline)',
        secretName: '/cloudhsm/workshop/rsakey',
      });
    } catch (error) {
      if (error instanceof Error && error.message.includes('already exists')) {
        // If the secret already exists, reference it
        rsaKey = secretsmanager.Secret.fromSecretNameV2(
          this,
          'existingRsaKey',
          '/cloudhsm/workshop/rsakey',
        ) as secretsmanager.Secret;
      } else {
        throw error;
      }
    }

    const selfSignedCert = new ssm.StringParameter(this, 'selfSignedCert', {
      description: 'Self Signed Certificate for root CA',
      parameterName: '/cloudhsm/workshop/selfsignedcert',
      stringValue: 'placeholder',
    });

    // Grant read and write permissions to the initializeClusterProvider
    rsaKey.grantRead(this.initializeClusterProvider.onEventHandler);
    rsaKey.grantWrite(this.initializeClusterProvider.onEventHandler);
    selfSignedCert.grantRead(this.initializeClusterProvider.onEventHandler);
    selfSignedCert.grantWrite(this.initializeClusterProvider.onEventHandler);

    const initializedCluster = new cdk.CustomResource(
      this,
      'initializeClusterCR',
      {
        serviceToken: this.initializeClusterProvider.serviceToken,
        properties: {
          RSASecret: rsaKey.secretArn,
          SelfSignedCert: selfSignedCert.parameterName,
          ClusterId: clusterId,
        },
      },
    );

    initializedCluster.node.addDependency(rsaKey);
    initializedCluster.node.addDependency(selfSignedCert);

    return { rsaKey, selfSignedCert, initializedCluster };
  }

  private createCloudHsmReadyGate(clusterId: string): cdk.CustomResource {
    // Create the ready gate resource
    const readyGate = new cdk.CustomResource(this, 'ClusterReadyGate', {
      serviceToken: this.clusterReadyProvider.serviceToken,
      properties: {
        ClusterId: clusterId,
      },
    });

    return readyGate;
  }

  private activateCluster(
    instance: ec2.Instance,
    clusterId: string,
    hsmNodeIp: string,
  ): {
    coPassword: secretsmanager.Secret;
    cuPassword: secretsmanager.Secret;
    activatedClusterTarget: cdk.CustomResource;
  } {
    const coPassword = new secretsmanager.Secret(this, 'coPassword', {
      description: 'Crypto Officer password',
      secretName: '/cloudhsm/workshop/copassword',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ type: 'CO', username: 'admin' }),
        generateStringKey: 'password',
        excludeCharacters: '"\';=:-',
      },
    });

    const cuPassword = new secretsmanager.Secret(this, 'cuPassword', {
      description: 'Crypto User password',
      secretName: '/cloudhsm/workshop/cupassword',
      generateSecretString: {
        secretStringTemplate: JSON.stringify({
          type: 'CU',
          username: 'crypto_user',
        }),
        generateStringKey: 'password',
        excludeCharacters: '"\';=:-',
      },
    });

    const runDocumentLogs = new logs.LogGroup(this, 'shellscriptLogs', {
      retention: logs.RetentionDays.ONE_WEEK,
    });

    const activateScriptAsset = new Asset(this, 'activateScript', {
      path: path.join(
        './custom_resources/activate_cluster/activate_cluster.sh',
      ),
    });

    activateScriptAsset.grantRead(this.adminInstance.role);
    runDocumentLogs.grantWrite(this.activateClusterProvider.onEventHandler);

    const targetActivatedCluster = new cdk.CustomResource(
      this,
      'activateCluster',
      {
        serviceToken: this.activateClusterProvider.serviceToken,
        properties: {
          InstanceId: instance.instanceId,
          COSecret: coPassword.secretName,
          CUSecret: cuPassword.secretName,
          ScriptAssetURL: activateScriptAsset.s3ObjectUrl,
          SelfSignedParamName: this.selfSignedCert.parameterName,
          HSMIpAddress: hsmNodeIp,
          LogGroupName: runDocumentLogs.logGroupName,
          ClusterId: clusterId,
        },
      },
    );

    targetActivatedCluster.node.addDependency(coPassword);
    targetActivatedCluster.node.addDependency(cuPassword);

    return {
      coPassword,
      cuPassword,
      activatedClusterTarget: targetActivatedCluster,
    };
  }

  private createAdminInstanceRole(): iam.IRole {
    const cloudHSMPolicy = new iam.Policy(this, 'adminBaseCloudHSMPolicy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['cloudhsm:DescribeClusters'],
          effect: iam.Effect.ALLOW,
          resources: ['*'],
        }),
      ],
    });

    const secretsManagerPolicy = new iam.Policy(
      this,
      'adminSecretsManagerPolicy',
      {
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: [
              'secretsmanager:CreateSecret',
              'secretsmanager:DescribeSecret',
              'secretsmanager:GetSecretValue',
              'secretsmanager:ListSecretVersionIds',
              'secretsmanager:ListSecrets',
            ],
            resources: [
              `arn:aws:secretsmanager:${this.region}:${this.account}:secret:/cloudhsm/workshop/*`,
            ],
          }),
        ],
      },
    );

    const ec2AdminRole = new iam.Role(this, 'ec2AdminRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'AmazonSSMManagedInstanceCore',
        ),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMPatchAssociation'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMFullAccess'),
      ],
    });

    ec2AdminRole.attachInlinePolicy(cloudHSMPolicy);
    ec2AdminRole.attachInlinePolicy(secretsManagerPolicy);

    return ec2AdminRole;
  }

  private createClientInstanceRole(): iam.IRole {
    const ec2clientRole = new iam.Role(this, 'ec2clientRole', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName(
          'AmazonSSMManagedInstanceCore',
        ),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMPatchAssociation'),
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMFullAccess'),
      ],
    });

    const cloudHSMPolicy = new iam.Policy(this, 'clientBaseCloudHSMPolicy', {
      statements: [
        new iam.PolicyStatement({
          actions: ['cloudhsm:DescribeClusters'],
          effect: iam.Effect.ALLOW,
          resources: ['*'],
        }),
      ],
    });

    const kmsPolicy = new iam.Policy(this, 'clientKmsClientPolicy', {
      policyName: 'BaseKMSPolicy',
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'kms:CreateKey',
            'kms:CreateAlias',
            'kms:DeleteAlias',
            'kms:UpdateAlias',
            'kms:DescribeKey',
            'kms:GetParametersForImport',
            'kms:ImportKeyMaterial',
            'kms:DeleteImportedKeyMaterial',
            'kms:Encrypt',
            'kms:Decrypt',
            'kms:EnableKey',
            'kms:DisableKey',
            'kms:TagResource',
            'kms:UntagResource',
            'kms:ListResourceTags',
            'kms:ScheduleKeyDeletion',
            'kms:CancelKeyDeletion',
            'kms:ListKeys',
            'kms:ListAliases',
          ],
          resources: ['*'],
        }),
      ],
    });

    const secretsManagerPolicy = new iam.Policy(
      this,
      'clientSecretsManagerPolicy',
      {
        statements: [
          new iam.PolicyStatement({
            effect: iam.Effect.ALLOW,
            actions: [
              'secretsmanager:CreateSecret',
              'secretsmanager:DescribeSecret',
              'secretsmanager:GetSecretValue',
              'secretsmanager:ListSecretVersionIds',
              'secretsmanager:ListSecrets',
            ],
            resources: [
              `arn:aws:secretsmanager:${this.region}:${this.account}:secret:/cloudhsm/workshop/*`,
            ],
          }),
        ],
      },
    );

    ec2clientRole.attachInlinePolicy(kmsPolicy);
    ec2clientRole.attachInlinePolicy(secretsManagerPolicy);
    ec2clientRole.attachInlinePolicy(cloudHSMPolicy);

    return ec2clientRole;
  }

  private createClientInstance(
    vpc: ec2.IVpc,
    instanceSG: ec2.ISecurityGroup,
    instanceType: string,
    instanceRole: iam.IRole,
  ): ec2.Instance {
    const ubuntuAMI = ec2.MachineImage.fromSsmParameter(
      '/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id',
      { os: ec2.OperatingSystemType.LINUX },
    );

    const lb = new elbv2.NetworkLoadBalancer(this, 'tlsOffloadLoadBalancer', {
      vpc: this.vpc,
      internetFacing: true,
    });

    const listener = lb.addListener('tlsOffloadListener', {
      port: 443,
    });

    const clientInstance = new ec2.Instance(this, 'clientInstanceUbuntu', {
      instanceType: new ec2.InstanceType(instanceType),
      machineImage: ubuntuAMI,
      vpc: vpc,
      role: instanceRole,
      securityGroup: instanceSG,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
    });

    listener.addTargets('ubuntuClientTarget', {
      port: 443,
      targets: [new targets.InstanceTarget(clientInstance, 443)],
      healthCheck: {
        enabled: true,
        healthyThresholdCount: 2,
        unhealthyThresholdCount: 2,
        interval: cdk.Duration.seconds(10),
      },
    });
    return clientInstance;
  }
  private createAdminInstance(
    vpc: ec2.IVpc,
    instanceSG: ec2.ISecurityGroup,
    instanceType: string,
    instanceRole: iam.IRole,
  ): ec2.Instance {
    const amznLinux = ec2.MachineImage.latestAmazonLinux2({
      edition: ec2.AmazonLinuxEdition.STANDARD,
      virtualization: ec2.AmazonLinuxVirt.HVM,
      storage: ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
      cpuType: ec2.AmazonLinuxCpuType.X86_64,
    });

    const adminInstance = new ec2.Instance(this, 'adminInstance', {
      instanceType: new ec2.InstanceType(instanceType),
      machineImage: amznLinux,
      vpc: vpc,
      role: instanceRole,
      securityGroup: instanceSG,
      vpcSubnets: {
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
      },
    });

    return adminInstance;
  }

  private addCloudHsmPolicies(lambdaFunction: lambda.Function): void {
    lambdaFunction.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'cloudhsm:*',
          'ec2:CreateNetworkInterface',
          'ec2:DescribeNetworkInterfaces',
          'ec2:DescribeNetworkInterfaceAttribute',
          'ec2:DetachNetworkInterface',
          'ec2:DeleteNetworkInterface',
          'ec2:CreateSecurityGroup',
          'ec2:AuthorizeSecurityGroupIngress',
          'ec2:AuthorizeSecurityGroupEgress',
          'ec2:RevokeSecurityGroupEgress',
          'ec2:DescribeSecurityGroups',
          'ec2:DeleteSecurityGroup',
          'ec2:CreateTags',
          'ec2:DescribeVpcs',
          'ec2:DescribeSubnets',
          'ec2:DescribeVpcEndpointServices',
          'iam:CreateServiceLinkedRole',
        ],
        resources: ['*'],
      }),
    );
  }

  private getOnePrivateSubnetPerAZ(): ec2.ISubnet[] {
    const allPrivateSubnets = this.vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
    }).subnets;

    // Create a map to store one subnet per AZ
    const subnetPerAZ = new Map<string, ec2.ISubnet>();

    // Iterate through all private subnets
    allPrivateSubnets.forEach((subnet) => {
      const az = subnet.availabilityZone;

      // If we haven't stored a subnet for this AZ yet, or if this subnet's ID is "smaller"
      // (arbitrary choice to ensure consistency), update the map
      if (
        !subnetPerAZ.has(az) ||
        subnet.subnetId < subnetPerAZ.get(az)!.subnetId
      ) {
        subnetPerAZ.set(az, subnet);
      }
    });

    // Convert the map back to an array and return
    return Array.from(subnetPerAZ.values());
  }

  private createOutputs(): void {
    new cdk.CfnOutput(this, 'ClusterSecurityGroupId', {
      value: this.clusterSG.securityGroupId,
      description: 'CloudHSM Cluster Security Group ID',
      exportName: 'CloudHsmClusterSecurityGroupId',
    });

    new cdk.CfnOutput(this, 'EC2InstanceSecurityGroupId', {
      value: this.ec2InstanceSG.securityGroupId,
      description: 'EC2 Instance Security Group ID',
      exportName: 'CloudHsmEC2InstanceSecurityGroupId',
    });

    new cdk.CfnOutput(this, 'ClusterIdParameterName', {
      value: this.clusterIdParam.parameterName,
      description: 'CloudHSM Cluster ID Parameter Name',
      exportName: 'CloudHsmClusterIdParameterName',
    });

    new cdk.CfnOutput(this, 'SelfSignedCertParameterName', {
      value: this.selfSignedCert.parameterName,
      description: 'Self-Signed Certificate Parameter Name',
      exportName: 'CloudHsmSelfSignedCertParameterName',
    });

    new cdk.CfnOutput(this, 'CUPasswordSecretName', {
      value: this.cuPassword.secretName,
      description: 'Crypto User Password Secret Name',
      exportName: 'CloudHsmCUPasswordSecretName',
    });
  }
}
