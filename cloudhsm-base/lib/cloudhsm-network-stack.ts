import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as ec2 from 'aws-cdk-lib/aws-ec2';

const VPC_CIDR = '10.0.0.0/16';
const SUBNET_CIDR_MASK = 24;

export interface CloudHsmNetworkStackProps extends cdk.StackProps {
  region: string;
  availabilityZones: string[];
  maxAzs: number;
}

export class CloudHsmNetworkStack extends cdk.Stack {
  public readonly vpc: ec2.IVpc;
  public readonly privateSubnets: ec2.ISubnet[];
  public readonly publicSubnets: ec2.ISubnet[];
  public readonly maxAzs: number;
  // Public CfnOutputs
  public vpcIdOutput: cdk.CfnOutput;
  public privateSubnetIdsOutput: cdk.CfnOutput;
  public publicSubnetIdsOutput: cdk.CfnOutput;
  public availabilityZonesOutput: cdk.CfnOutput;
  private _availabilityZones: string[];

  constructor(scope: Construct, id: string, props: CloudHsmNetworkStackProps) {
    super(scope, id, props);
    this.maxAzs = props.maxAzs;

    const availabilityZones = props.availabilityZones.slice(0, this.maxAzs);
    this._availabilityZones = availabilityZones;

    this.vpc = this.createVpc(availabilityZones);
    this.privateSubnets = this.getSubnets(ec2.SubnetType.PRIVATE_WITH_EGRESS);
    this.publicSubnets = this.getSubnets(ec2.SubnetType.PUBLIC);

    this.createOutputs();
  }

  private createVpc(availabilityZones: string[]): ec2.IVpc {
    return new ec2.Vpc(this, 'ClusterVPC', {
      ipAddresses: ec2.IpAddresses.cidr(VPC_CIDR),
      availabilityZones: availabilityZones,
      subnetConfiguration: [
        {
          cidrMask: SUBNET_CIDR_MASK,
          name: 'Public',
          subnetType: ec2.SubnetType.PUBLIC,
        },
        {
          cidrMask: SUBNET_CIDR_MASK,
          name: 'PrivateWithEgress1',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
        {
          cidrMask: SUBNET_CIDR_MASK,
          name: 'PrivateWithEgress2',
          subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        },
      ],
      natGateways: availabilityZones.length,
    });
  }

  private getSubnets(subnetType: ec2.SubnetType): ec2.ISubnet[] {
    return this.vpc.selectSubnets({ subnetType: subnetType }).subnets;
  }

  private getAvailabilityZones(): string[] {
    return this._availabilityZones;
  }

  private createOutputs(): void {
    this.vpcIdOutput = new cdk.CfnOutput(this, 'VpcId', {
      value: cdk.Token.asString(this.vpc.vpcId),
      description: 'VPC ID',
      exportName: 'CloudHsmVpcId',
    });

    this.privateSubnetIdsOutput = new cdk.CfnOutput(this, 'PrivateSubnetIds', {
      value: this.privateSubnets.map((subnet) => subnet.subnetId).join(','),
      description: 'Private Subnet IDs',
      exportName: 'CloudHsmPrivateSubnetIds',
    });

    this.publicSubnetIdsOutput = new cdk.CfnOutput(this, 'PublicSubnetIds', {
      value: this.publicSubnets.map((subnet) => subnet.subnetId).join(','),
      description: 'Public Subnet IDs',
      exportName: 'CloudHsmPublicSubnetIds',
    });

    this.availabilityZonesOutput = new cdk.CfnOutput(
      this,
      'AvailabilityZones',
      {
        value: this._availabilityZones.join(','),
        description: 'Actual Availability Zones used for VPC deployment',
        exportName: 'CloudHsmAvailabilityZones',
      },
    );
  }
}
