import * as cdk from '@aws-cdk/core';
import * as ec2 from '@aws-cdk/aws-ec2';
import * as iam from '@aws-cdk/aws-iam';
import * as lambda from '@aws-cdk/aws-lambda';
import * as custom from '@aws-cdk/custom-resources';
import * as ssm from '@aws-cdk/aws-ssm';
import * as secret from '@aws-cdk/aws-secretsmanager';
import { Asset } from '@aws-cdk/aws-s3-assets';
import * as path from 'path';
import * as logs from '@aws-cdk/aws-logs';
import { DockerImageAsset } from '@aws-cdk/aws-ecr-assets';
import * as ecs from '@aws-cdk/aws-ecs';

export class CloudhsmBaseStack extends cdk.Stack {
  constructor(scope: cdk.Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    const vpc = new ec2.Vpc(this, 'ClusterVPC',{
      cidr: "10.0.0.0/16",
      maxAzs: 2
    });

    const privateSubnetList = vpc.selectSubnets({
      subnetType: ec2.SubnetType.PRIVATE
    });


    // EC2 Role for SSM
    const ec2admin_role = new iam.Role(this, 'ec2admin_role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this,'ec2amin_role_policy','arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
      ]
    });

    const ec2client_role = new iam.Role(this, 'ec2client_role', {
      assumedBy: new iam.ServicePrincipal('ec2.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromManagedPolicyArn(this,'ec2client_role_policy','arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM')
      ]
    });    

    const basicCloudHSMPolicy = new iam.Policy(this, 'baseCloudHSMPolicy', {
      policyName: 'BaseCloudHSMPolicy',
      statements: [
        new iam.PolicyStatement({
          actions: [
            "cloudhsm:DescribeClusters"
          ],
          effect: iam.Effect.ALLOW,
          resources: ['*']
        })
      ],
      roles: [
        ec2client_role,
        ec2admin_role
      ]
    });

    const amznLinux = ec2.MachineImage.latestAmazonLinux({
      generation: ec2.AmazonLinuxGeneration.AMAZON_LINUX_2,
      edition: ec2.AmazonLinuxEdition.STANDARD,
      virtualization: ec2.AmazonLinuxVirt.HVM,
      storage: ec2.AmazonLinuxStorage.GENERAL_PURPOSE,
      cpuType: ec2.AmazonLinuxCpuType.X86_64,
    });

    const ubuntu = ec2.MachineImage.fromSSMParameter(
      '/aws/service/canonical/ubuntu/server/18.04/stable/current/amd64/hvm/ebs-gp2/ami-id',
      ec2.OperatingSystemType.LINUX);





    const ec2InstanceSG = new ec2.SecurityGroup(this, 'ec2InstanceSG', {
      vpc: vpc,
      description: 'CloudHSM Admin Instance',
      allowAllOutbound: true
    });

    //ec2InstanceSG.addIngressRule(ec2.Peer.anyIpv4(),ec2.Port.tcp(22),'Allow SSH Inbound');
    ec2InstanceSG.addIngressRule(ec2.Peer.anyIpv4(),ec2.Port.tcp(443),'Allow HTTPS Inbound');

    const adminInstance = new ec2.Instance(this, 'adminInstance', {
      instanceType: new ec2.InstanceType("t3.nano"),
      machineImage: amznLinux,
      vpc: vpc,
      role: ec2admin_role,
      securityGroup: ec2InstanceSG,
      vpcSubnets: {
        subnets: [vpc.privateSubnets[0]]
      }
    });    

    const clientInstance = new ec2.Instance(this, 'clientInstance', {
      instanceType: new ec2.InstanceType("t3.nano"),
      machineImage: amznLinux,
      vpc: vpc,
      role: ec2client_role,
      securityGroup: ec2InstanceSG,
      vpcSubnets: {
        subnets: [vpc.privateSubnets[1]]
      }
    });      

    const clientInstanceUbuntu = new ec2.Instance(this, 'clientInstanceUbuntu', {
      instanceType: new ec2.InstanceType("t3.nano"),
      machineImage: ubuntu,
      vpc: vpc,
      role: ec2client_role,
      securityGroup: ec2InstanceSG,
      vpcSubnets: {
        subnets: [vpc.privateSubnets[1]]
      }
    });

    const cloudHsmClusterFunction = new lambda.Function(this, 'cloudHSMProvider', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cloudhsm_cluster/'),
      handler: 'lambda_function.handler'
    });

    if (cloudHsmClusterFunction.role) {
      cloudHsmClusterFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "cloudhsm:DescribeClusters",
          "cloudhsm:DescribeBackups",
          "cloudhsm:CreateCluster",
          "cloudhsm:CreateHsm",
          "cloudhsm:RestoreBackup",
          "cloudhsm:CopyBackupToRegion",
          "cloudhsm:InitializeCluster",
          "cloudhsm:ListTags",
          "cloudhsm:TagResource",
          "cloudhsm:UntagResource",
          "cloudhsm:DeleteCluster",
          "cloudhsm:DeleteBackup",
          "cloudhsm:DeleteHsm",
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeNetworkInterfaceAttribute",
          "ec2:DetachNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateTags",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "iam:CreateServiceLinkedRole"              
        ],
        resources: ["*"]
      }));
    }

    const cloudHsmClusterIsCompleteFunction = new lambda.Function(this, 'cloudHSMProviderIsComplete', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cloudhsm_cluster/'),
      handler: 'lambda_function.isComplete'      
    });

    if (cloudHsmClusterIsCompleteFunction.role) {
      cloudHsmClusterIsCompleteFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
            "cloudhsm:DescribeClusters",
            "cloudhsm:DeleteCluster",
            "ec2:DeleteNetworkInterface",
            "ec2:DeleteSecurityGroup"
        ],
        resources: ["*"]
      }));
    }

    const cloudhsmProvider = new custom.Provider(this, 'CloudHSMClusterProvider', {
      onEventHandler: cloudHsmClusterFunction,
      isCompleteHandler: cloudHsmClusterIsCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });



    const cloudHSMCluster = new cdk.CustomResource(this, 'cloudHSMClusterCR', {
      serviceToken: cloudhsmProvider.serviceToken,
      properties: {
        SubnetIds: privateSubnetList.subnetIds
      }
    });


    const clusterSG = ec2.SecurityGroup.fromSecurityGroupId(this,'CloudHSMClusterSG', cloudHSMCluster.getAttString('SecurityGroupId'));
    clusterSG.node.addDependency(cloudHSMCluster);
    adminInstance.addSecurityGroup(clusterSG);
    clientInstance.addSecurityGroup(clusterSG);
    clientInstanceUbuntu.addSecurityGroup(clusterSG);


    const cloudHsm1Function = new lambda.Function(this, 'cloudHSM1Provider', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cloudhsm_hsm/'),
      handler: 'lambda_function.handler'
    });

    if (cloudHsm1Function.role) {
      cloudHsm1Function.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "cloudhsm:DescribeClusters",
          "cloudhsm:DescribeBackups",
          "cloudhsm:CreateCluster",
          "cloudhsm:CreateHsm",
          "cloudhsm:RestoreBackup",
          "cloudhsm:CopyBackupToRegion",
          "cloudhsm:InitializeCluster",
          "cloudhsm:ListTags",
          "cloudhsm:TagResource",
          "cloudhsm:UntagResource",
          "cloudhsm:DeleteCluster",
          "cloudhsm:DeleteHsm",
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeNetworkInterfaceAttribute",
          "ec2:DetachNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:CreateSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeSecurityGroups",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateTags",
          "ec2:DescribeVpcs",
          "ec2:DescribeSubnets",
          "iam:CreateServiceLinkedRole"               
        ],
        resources: ["*"]
      }));
    }

    const cloudHsm1IsCompleteFunction = new lambda.Function(this, 'cloudHSM1ProviderIsComplete', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cloudhsm_hsm/'),
      handler: 'lambda_function.isComplete'      
    });

    if (cloudHsm1IsCompleteFunction.role) {
      cloudHsm1IsCompleteFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
            "cloudhsm:DescribeClusters",
            "cloudhsm:CreateHsm",
            "ec2:CreateNetworkInterface",
        ],
        resources: ["*"]
      }));
    }

    const cloudhsm1Provider = new custom.Provider(this, 'CloudHSM1Provider', {
      onEventHandler: cloudHsm1Function,
      isCompleteHandler: cloudHsm1IsCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

    const cloudHSM1 = new cdk.CustomResource(this, 'cloudHSMC1CR', {
      serviceToken: cloudhsm1Provider.serviceToken,
      properties: {
        ClusterId: cloudHSMCluster.getAttString("ClusterId")
      }
    });   


    const clusterIdParam = new ssm.StringParameter(this, 'clusterIdParam', {
      stringValue: cloudHSMCluster.getAttString("ClusterId"),
      parameterName: '/cloudhsm/workshop/clusterId'
    });

    clusterIdParam.grantRead(ec2admin_role);
    clusterIdParam.grantRead(ec2client_role);


    // Generate RSA Key and CO, CU Secrets in a lambda function.
    const initializeClusterFunction = new lambda.Function(this, 'initializeCluster', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/initialize_cluster/'),
      handler: 'lambda_function.handler',
      timeout: cdk.Duration.seconds(300)      // RSA Key generation take a little apparently depending on the underlying HW
    });

    if (initializeClusterFunction.role) {
      initializeClusterFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "cloudhsm:DescribeClusters",
          "cloudhsm:InitializeCluster",

        ],
        resources: ["*"] // Add Cluster ARN
      }));
    }

    const initializeClusterIsCompleteFunction = new lambda.Function(this, 'initializeClusterIsCompleteFunction', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/initialize_cluster/'),
      handler: 'lambda_function.isComplete'      
    });

    if (initializeClusterIsCompleteFunction.role) {
      initializeClusterIsCompleteFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
            "cloudhsm:DescribeClusters"
        ],
        resources: ["*"]
      }));
    }

    const generateKeysProvider = new custom.Provider(this, 'generateKeysProvider', {
      onEventHandler: initializeClusterFunction,
      isCompleteHandler: initializeClusterIsCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

   
    // Add KMS Key??
    // Value will be filled in a Lambda function with the Certificate
    const rsaKey = new secret.Secret(this, 'rsaKey', {
      description: "RSA Key used to sign HSM certificates. This key should be stored off-site (and offline)",
      secretName: "/cloudhsm/workshop/rsakey",
    });
    if (initializeClusterFunction.role) {
      initializeClusterFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "secretsmanager:PutSecretValue",         
        ],
        resources: [rsaKey.secretArn]
      }));
    }
    rsaKey.grantWrite(initializeClusterFunction);

    const selfSignedCert = new ssm.StringParameter(this, 'selfSignedCert', {
      description: 'Self Signed Certificate for root CA',
      parameterName: '/cloudhsm/workshop/selfsignedcert',
      stringValue: 'placeholder'      // Will be populated with the RSA key by the Custom Resource
    });

    selfSignedCert.grantRead(ec2admin_role);
    selfSignedCert.grantRead(ec2client_role);

    if (initializeClusterFunction.role) {
      initializeClusterFunction.role.addToPrincipalPolicy(new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "ssm:PutParameter",         
        ],
        resources: [selfSignedCert.parameterArn]
      }));
    }
    selfSignedCert.grantWrite(initializeClusterFunction);


    const initializeCluster = new cdk.CustomResource(this, 'initializeClusterCR', {
      serviceToken: generateKeysProvider.serviceToken,
      properties: {
        RSASecret: rsaKey.secretName,
        SelfSignedCert: selfSignedCert.parameterName,
        ClusterId: cloudHSMCluster.getAttString("ClusterId"),
        HSMId: cloudHSM1.getAttString("HsmId")
      }
    }); 
    initializeCluster.node.addDependency(cloudHSM1)

    const coPassword = new secret.Secret(this, 'coPassword', {
      description: "Crypto Officer password",
      secretName: "/cloudhsm/workshop/copassowrd",
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ type: 'CO', username: 'admin'}),
        generateStringKey: 'password',
        excludeCharacters: '"\';=:-'
      }
    });
    coPassword.grantRead(ec2admin_role);

    const cuPassword = new secret.Secret(this, 'cuPassword', {
      description: "Crypto User password",
      secretName: "/cloudhsm/workshop/cupassowrd",
      generateSecretString: {
        secretStringTemplate: JSON.stringify({ type: 'CU', username: 'client'}),
        generateStringKey: 'password',
        excludeCharacters: '"\';=:-'
      }
    });
    cuPassword.grantRead(ec2admin_role);
    cuPassword.grantRead(ec2client_role);

    const runDocumentLogs = new logs.LogGroup(this,'shellscriptLogs', {
      retention: logs.RetentionDays.ONE_WEEK
    });


    const activateScriptAsset = new Asset(this, 'activateScript', {
      path: path.join(__dirname,'../../custom_resources/cloudHSMActivate.expect')
    });

    
    const activateClusterFunction = new lambda.Function(this, 'activateClusterFunction', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/activate_cluster'),
      handler: 'lambda_function.handler'
    });
  
    runDocumentLogs.grantWrite(activateClusterFunction);

    activateClusterFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      resources: ["*"]
    }));

    const activateClusterCompleteFunction = new lambda.Function(this, 'activateClusterCompleteFunction', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/activate_cluster'),
      handler: 'lambda_function.isComplete'
    });

    activateClusterCompleteFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      resources: ["*"]
    }));

    const activateClusterProvider = new custom.Provider(this,'activateClusterProvider', {
      onEventHandler: activateClusterFunction,
      isCompleteHandler: activateClusterCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

    const activateCluster = new cdk.CustomResource(this,'activateCluster', {
      serviceToken: activateClusterProvider.serviceToken,
      properties: {
        InstanceId : adminInstance.instanceId,
        COSecret: coPassword.secretName,
        CUSecret: cuPassword.secretName,
        ExpectAssetURL: activateScriptAsset.s3ObjectUrl,
        SelfSignedParamName: selfSignedCert.parameterName,
        HSMIpAddress: cloudHSM1.getAttString("EniIp"),
        LogGroupName: runDocumentLogs.logGroupName
      }
    });
    activateCluster.node.addDependency(initializeCluster);


    const cloudHsmReadyFunction = new lambda.Function(this, 'cloudHSMReadyProvider', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cluster_ready_gate/'),
      handler: 'lambda_function.handler'
    });

    cloudHsmReadyFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
          "cloudhsm:DescribeClusters"
      ],
      resources: ["*"]
    }));

    const cloudHsmReadyIsCompleteFunction = new lambda.Function(this, 'cloudHSMReadyIsCompleteProvider', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/cluster_ready_gate/'),
      handler: 'lambda_function.isComplete'
    });

    cloudHsmReadyIsCompleteFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
          "cloudhsm:DescribeClusters"
      ],
      resources: ["*"]
    }));

    const cloudHsmReadyProvider = new custom.Provider(this,'cloudHsmReadyProvider', {
      onEventHandler: cloudHsmReadyFunction,
      isCompleteHandler: cloudHsmReadyIsCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

    const cloudHSMClusterReady = new cdk.CustomResource(this,'cloudHSMReadyGateCR', {
      serviceToken: cloudHsmReadyProvider.serviceToken,
      properties: {
        ClusterId: cloudHSMCluster.getAttString("ClusterId")
      }
    });
    cloudHSMClusterReady.node.addDependency(cloudHSM1);

    const cloudhsm2Provider = new custom.Provider(this, 'CloudHSM2Provider', {
      onEventHandler: cloudHsm1Function,
      isCompleteHandler: cloudHsm1IsCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

    const cloudHSM2 = new cdk.CustomResource(this, 'cloudHSMC2CR', {
      serviceToken: cloudhsm2Provider.serviceToken,
      properties: {
        ClusterId: cloudHSMCluster.getAttString("ClusterId")
      }
    });   
    cloudHSM2.node.addDependency(cloudHSMClusterReady);

    const bootstrapFunction = new lambda.Function(this, 'bootstrapFunction', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/bootstrap_instances'),
      handler: 'lambda_function.handler'
    });
    runDocumentLogs.grantWrite(bootstrapFunction);

    bootstrapFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      resources: ["*"]
    }));

    const bootstrapCompleteFunction = new lambda.Function(this, 'bootstrapCompleteFunction', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/bootstrap_instances'),
      handler: 'lambda_function.isComplete'
    });

    bootstrapCompleteFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "ssm:SendCommand",
        "ssm:GetCommandInvocation"
      ],
      resources: ["*"]
    }));

    const bootstrapInstanceProvider = new custom.Provider(this,'bootstrapInstanceProvider', {
      onEventHandler: bootstrapFunction,
      isCompleteHandler: bootstrapCompleteFunction,
      queryInterval: cdk.Duration.seconds(60)
    });

    const bootstrapClientInstance = new cdk.CustomResource(this,'bootstrapClientInstance', {
      serviceToken: bootstrapInstanceProvider.serviceToken,
      properties: {
        InstanceId : clientInstance.instanceId,
        SelfSignedParamName: selfSignedCert.parameterName,
        HSMIpAddress: cloudHSM1.getAttString("EniIp"),
        LogGroupName: runDocumentLogs.logGroupName,
        OSType: "AmazonLinux2"
      }
    });
    bootstrapClientInstance.node.addDependency(cloudHSM2);    

    // Demo App Container image

    const ecsServiceRoleCheckFunction = new lambda.Function(this, 'ecsServiceRoleCheck', {
      runtime: lambda.Runtime.PYTHON_3_8,
      code: lambda.Code.fromAsset('../custom_resources/ecs_service_role'),
      handler: 'lambda_function.handler'
    });

    ecsServiceRoleCheckFunction.role?.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        "iam:CreateServiceLinkedRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "iam:GetRole"

      ],
      resources: ["*"]
    }));

    const ecsServiceRoleProvider = new custom.Provider(this,'ecsServiceRoleProvider', {
      onEventHandler: ecsServiceRoleCheckFunction
    });

    const ecsServiceRoleCR = new cdk.CustomResource(this,'ecsServiceRoleCR', {
      serviceToken: ecsServiceRoleProvider.serviceToken
    });

    const ecsCloudHSMTestCluster = new ecs.Cluster(this, "CloudHSMTest", {
      vpc: vpc,
      containerInsights: true
  });
    
    const logging = new ecs.AwsLogDriver({
      streamPrefix: "logs",
      logGroup: new logs.LogGroup(this, "ecs-log-group", {
        logGroupName: "/ecs/cloudhsm-sample",
        removalPolicy: cdk.RemovalPolicy.DESTROY
      })
    });

    const taskRole = new iam.Role(this, `taskRole`, {
      assumedBy: new iam.ServicePrincipal('ecs-tasks.amazonaws.com')
    });
    clusterIdParam.grantRead(taskRole);
    selfSignedCert.grantRead(taskRole);
    cuPassword.grantRead(taskRole);
    taskRole.addToPrincipalPolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
          "cloudhsm:DescribeClusters",
      ],
      resources: ["*"]
    }));
    
    

    const taskDefinition = new ecs.FargateTaskDefinition(this, "taskDefinition", {
      cpu: 256,
      taskRole: taskRole,
      memoryLimitMiB: 1024
    });

    taskDefinition.addContainer('container', {
      image: ecs.ContainerImage.fromAsset(path.join(__dirname, '../../examples/pkcs11-5.0-sample/')),
      memoryLimitMiB: 512,
      cpu: 256,
      logging: logging,
      environment: { // clear text, not for sensitive data
        AWS_REGION: this.region,
      }
    });

    const ecsService = new ecs.FargateService(this, 'sampleService', {
      cluster: ecsCloudHSMTestCluster,
      taskDefinition: taskDefinition,
      securityGroups: [clusterSG, ec2InstanceSG],
      desiredCount: 0,
    })


    // const bootstrapClientInstanceUbuntu = new cdk.CustomResource(this,'bootstrapClientInstanceUbuntu', {
    //   serviceToken: bootstrapInstanceProvider.serviceToken,
    //   properties: {
    //     InstanceId : clientInstanceUbuntu.instanceId,
    //     SelfSignedParamName: selfSignedCert.parameterName,
    //     HSMIpAddress: cloudHSM1.getAttString("EniIp"),
    //     LogGroupName: runDocumentLogs.logGroupName,
    //     OSType: "Ubuntu"
    //   }
    // });
    // bootstrapClientInstanceUbuntu.node.addDependency(cloudHSM2);  

  }
  private createOuputs(params: Map<string, string>) {
    params.forEach((value, key) => {
        new cdk.CfnOutput(this, key, { value: value })
    });
  }    
}
