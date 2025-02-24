import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as custom from 'aws-cdk-lib/custom-resources';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as ecs from 'aws-cdk-lib/aws-ecs';
import * as path from 'path';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

export interface EcsTestStackProps extends cdk.StackProps {
  vpc: ec2.IVpc;
  clusterSG: ec2.ISecurityGroup;
  ec2InstanceSG: ec2.ISecurityGroup;
  clusterIdParam: ssm.IStringParameter;
  selfSignedCert: ssm.IStringParameter;
  cuPassword: secretsmanager.ISecret;
}

export class EcsTestStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: EcsTestStackProps) {
    super(scope, id, props);

    const LAMBDA_PYTHON_RUNTIME = lambda.Runtime.PYTHON_3_13;

    const ecsServiceRoleCheckFunction = new lambda.Function(
      this,
      'ecsServiceRoleCheck',
      {
        runtime: LAMBDA_PYTHON_RUNTIME,
        code: lambda.Code.fromAsset('./custom_resources/ecs_service_role'),
        handler: 'lambda_function.handler',
      },
    );

    ecsServiceRoleCheckFunction.role?.addToPrincipalPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          'iam:CreateServiceLinkedRole',
          'iam:AttachRolePolicy',
          'iam:PutRolePolicy',
          'iam:GetRole',
        ],
        resources: ['*'],
      }),
    );

    const ecsServiceRoleProvider = new custom.Provider(
      this,
      'ecsServiceRoleProvider',
      {
        onEventHandler: ecsServiceRoleCheckFunction,
      },
    );

    const ecsServiceRoleCR = new cdk.CustomResource(this, 'ecsServiceRoleCR', {
      serviceToken: ecsServiceRoleProvider.serviceToken,
    });

    const ecsCloudHSMTestCluster = new ecs.Cluster(this, 'CloudHSMTest', {
      vpc: props.vpc,
      containerInsights: true,
    });

    const logging = new ecs.AwsLogDriver({
      streamPrefix: 'logs',
      logGroup: new logs.LogGroup(this, 'ecs-log-group', {
        logGroupName: '/ecs/cloudhsm-sample',
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      }),
    });

    const taskRole = new iam.Role(this, 'taskRole', {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com'),
      roleName: cdk.PhysicalName.GENERATE_IF_NEEDED,
    });
    props.clusterIdParam.grantRead(taskRole);
    props.selfSignedCert.grantRead(taskRole);
    props.cuPassword.grantRead(taskRole);

    taskRole.addToPrincipalPolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['cloudhsm:DescribeClusters'],
        resources: ['*'],
      }),
    );

    const taskDefinition = new ecs.FargateTaskDefinition(
      this,
      'taskDefinition',
      {
        cpu: 256,
        taskRole: taskRole,
        memoryLimitMiB: 1024,
      },
    );

    taskDefinition.addContainer('container', {
      image: ecs.ContainerImage.fromAsset(
        path.join(__dirname, './../pkcs11-5.0-sample/'),
      ),
      memoryLimitMiB: 512,
      cpu: 256,
      logging: logging,
      environment: {
        AWS_REGION: this.region,
      },
    });

    const ecsService = new ecs.FargateService(this, 'sampleService', {
      cluster: ecsCloudHSMTestCluster,
      taskDefinition: taskDefinition,
      securityGroups: [props.clusterSG, props.ec2InstanceSG],
      desiredCount: 0,
    });
  }
}
