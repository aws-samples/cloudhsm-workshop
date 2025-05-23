import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ssm from 'aws-cdk-lib/aws-ssm';
import * as iam from 'aws-cdk-lib/aws-iam';

export class WindowsSystemsManagerQuickSetupStack extends cdk.Stack {
  public readonly managedInstanceRole: cdk.aws_iam.Role;
  public readonly automationServiceRole: cdk.aws_iam.Role;

  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Get the current account ID and region for use in configuration
    const account = cdk.Stack.of(this).account;
    const region = cdk.Stack.of(this).region;
    const configId = 'cloudhsmwin' + cdk.Names.uniqueId(this).substring(0, 5).toLowerCase();

    // Create the automation service role for enabling default SSM
    this.automationServiceRole = new iam.Role(this, 'AutomationServiceRole', {
      roleName: `AutomationServiceRole-EnableDefaultSSM-${region}`,
      assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com'),
      description: 'Role used by SSM automation to enable default EC2 instance management'
    });

    // Create the managed instance role for SSM default management
    this.managedInstanceRole = new iam.Role(this, 'ManagedInstanceRole', {
      roleName: 'AWSSystemsManagerDefaultEC2InstanceManagementRole',
      assumedBy: new iam.ServicePrincipal('ssm.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonSSMManagedEC2InstanceDefaultPolicy')
      ],
      description: 'Role created by SSM to manage EC2 instances by default'
    });

    // Add policy to the automation service role
    const automationPolicy = new iam.Policy(this, 'AutomationServiceRolePolicy', {
      policyName: 'enableDefaultSSM',
      statements: [
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'ssm:GetServiceSetting',
            'ssm:UpdateServiceSetting'
          ],
          resources: [
            `arn:${cdk.Stack.of(this).partition}:ssm:*:${account}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role`
          ]
        }),
        new iam.PolicyStatement({
          effect: iam.Effect.ALLOW,
          actions: [
            'iam:PassRole'
          ],
          resources: [this.managedInstanceRole.roleArn],
          conditions: {
            StringLikeIfExists: {
              'iam:PassedToService': 'ssm.amazonaws.com'
            }
          }
        })
      ]
    });

    automationPolicy.attachToRole(this.automationServiceRole);

    // Create the SSM automation document for enabling default EC2 instance management
    const automationDocument = new ssm.CfnDocument(this, 'AutomationRunbookEnableDefaultSSM', {
      documentType: 'Automation',
      content: {
        description: 'This document updates the Systems Manager service setting `default-ec2-instance-management-role`.',
        schemaVersion: '0.3',
        assumeRole: '{{ AutomationAssumeRole }}',
        parameters: {
          AutomationAssumeRole: {
            type: 'AWS::IAM::Role::Arn',
            description: '(Required) The ARN of the role that allows Automation to perform the actions on your behalf.',
            default: this.automationServiceRole.roleArn
          },
          DefaultEC2InstanceManagementRoleName: {
            type: 'String',
            description: '(Required) The name of the default EC2 instance management role.',
            default: this.managedInstanceRole.roleName
          }
        },
        mainSteps: [
          {
            name: 'checkExistingServiceSetting',
            action: 'aws:executeAwsApi',
            onFailure: 'Abort',
            inputs: {
              Service: 'ssm',
              Api: 'GetServiceSetting',
              SettingId: `arn:${cdk.Stack.of(this).partition}:ssm:${region}:${account}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role`
            },
            outputs: [
              {
                Name: 'ServiceSettingValue',
                Type: 'String',
                Selector: '$.ServiceSetting.SettingValue'
              }
            ]
          },
          {
            name: 'branchOnSetting',
            action: 'aws:branch',
            isEnd: true,
            inputs: {
              Choices: [
                {
                  NextStep: 'updateServiceSetting',
                  Not: {
                    Variable: '{{ checkExistingServiceSetting.ServiceSettingValue }}',
                    StringEquals: '{{ DefaultEC2InstanceManagementRoleName }}'
                  }
                }
              ]
            }
          },
          {
            name: 'updateServiceSetting',
            action: 'aws:executeAwsApi',
            onFailure: 'Abort',
            inputs: {
              Service: 'ssm',
              Api: 'UpdateServiceSetting',
              SettingId: `arn:${cdk.Stack.of(this).partition}:ssm:${region}:${account}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role`,
              SettingValue: '{{ DefaultEC2InstanceManagementRoleName }}'
            }
          },
          {
            name: 'confirmServiceSetting',
            action: 'aws:executeAwsApi',
            onFailure: 'Abort',
            inputs: {
              Service: 'ssm',
              Api: 'GetServiceSetting',
              SettingId: `arn:${cdk.Stack.of(this).partition}:ssm:${region}:${account}:servicesetting/ssm/managed-instance/default-ec2-instance-management-role`
            },
            outputs: [
              {
                Name: 'ServiceSetting',
                Type: 'StringMap',
                Selector: '$.ServiceSetting'
              }
            ]
          }
        ]
      }
    });

    // Create association to run the automation document
    new ssm.CfnAssociation(this, 'UpdateDefaultEC2InstanceManagementAssociation', {
      name: automationDocument.ref,
      associationName: 'EnableDefaultEC2InstanceManagement',
      // Run once initially and then monthly to ensure the setting stays configured
      scheduleExpression: 'rate(30 days)'
    });

    // Create SSM association for SSM Agent updates
    const ssmAgentUpdateAssociation = new ssm.CfnAssociation(this, 'SSMAgentUpdateAssociation', {
      name: 'AWS-UpdateSSMAgent',
      associationName: `AWS-QuickSetup-SSM-UpdateSSMAgent-${configId}`,
      scheduleExpression: 'rate(14 days)',
      targets: [{
        key: 'InstanceIds',
        values: ['*']
      }]
    });

    // Create SSM association for inventory collection to enable Fleet Manager
    const inventoryCollectionAssociation = new ssm.CfnAssociation(this, 'SystemAssociationForInventoryCollection', {
      name: 'AWS-GatherSoftwareInventory',
      associationName: `AWS-QuickSetup-SSM-CollectInventory-${configId}`,
      scheduleExpression: 'rate(12 hours)',
      parameters: {
        applications: ['Enabled'],
        awsComponents: ['Enabled'],
        networkConfig: ['Enabled'],
        instanceDetailedInformation: ['Enabled'],
        windowsUpdates: ['Enabled'],
        services: ['Enabled'],
        windowsRoles: ['Enabled'],
        customInventory: ['Enabled']
      },
      targets: [{
        key: 'InstanceIds',
        values: ['*']
      }]
    });

    // Outputs for cross-stack references
    new cdk.CfnOutput(this, 'ManagedInstanceRoleName', {
      value: this.managedInstanceRole.roleName,
      description: 'SSM Default EC2 Instance Management Role Name',
      exportName: 'SsmDefaultEC2InstanceManagementRoleName',
    });

    new cdk.CfnOutput(this, 'InventoryAssociationName', {
      value: inventoryCollectionAssociation.associationName || '',
      description: 'SSM Inventory Collection Association Name',
      exportName: 'SsmInventoryAssociationName',
    });

    new cdk.CfnOutput(this, 'SSMAgentUpdateAssociationName', {
      value: ssmAgentUpdateAssociation.associationName || '',
      description: 'SSM Agent Update Association Name',
      exportName: 'SsmAgentUpdateAssociationName',
    });
  }
}
