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
    // VPC Endpoints
    public readonly ssmEndpoint: ec2.InterfaceVpcEndpoint;
    public readonly ec2MessagesEndpoint: ec2.InterfaceVpcEndpoint;
    public readonly ssmmessagesEndpoint: ec2.InterfaceVpcEndpoint;
    public readonly s3Endpoint: ec2.GatewayVpcEndpoint;
    public readonly cloudHSMEndpoint: ec2.InterfaceVpcEndpoint;
    public readonly endpointSecurityGroup: ec2.SecurityGroup;

    constructor(scope: Construct, id: string, props: CloudHsmNetworkStackProps) {
        super(scope, id, props);
        this.maxAzs = props.maxAzs;

        const availabilityZones = props.availabilityZones.slice(0, this.maxAzs);

        this._availabilityZones = availabilityZones;

        this.vpc = this.createVpc(availabilityZones);
        this.privateSubnets = this.getSubnets(ec2.SubnetType.PRIVATE_WITH_EGRESS);
        this.publicSubnets = this.getSubnets(ec2.SubnetType.PUBLIC);

        // Create VPC endpoints for SSM connectivity
        const endpoints = this.createVpcEndpoints();
        this.ssmEndpoint = endpoints.ssmEndpoint;
        this.ec2MessagesEndpoint = endpoints.ec2MessagesEndpoint;
        this.ssmmessagesEndpoint = endpoints.ssmmessagesEndpoint;
        this.s3Endpoint = endpoints.s3Endpoint;
        this.cloudHSMEndpoint = endpoints.cloudHSMEndpoint;
        this.endpointSecurityGroup = endpoints.endpointSecurityGroup;

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

    private createVpcEndpoints(): {
        ssmEndpoint: ec2.InterfaceVpcEndpoint;
        ec2MessagesEndpoint: ec2.InterfaceVpcEndpoint;
        ssmmessagesEndpoint: ec2.InterfaceVpcEndpoint;
        s3Endpoint: ec2.GatewayVpcEndpoint;
        cloudHSMEndpoint: ec2.InterfaceVpcEndpoint;
        endpointSecurityGroup: ec2.SecurityGroup;
    } {
        // Define security group for VPC endpoints
        const endpointSecurityGroup = new ec2.SecurityGroup(this, 'EndpointSecurityGroup', {
            vpc: this.vpc,
            description: 'Security Group for CloudHSM VPC Endpoints',
            allowAllOutbound: true,
        });

        // Add egress rules for HTTP and HTTPS traffic that EC2 instances need for SSM
        endpointSecurityGroup.addEgressRule(
            ec2.Peer.anyIpv4(),
            ec2.Port.tcp(443),
            'Allow HTTPS outbound traffic for SSM',
        );

        endpointSecurityGroup.addEgressRule(
            ec2.Peer.anyIpv4(),
            ec2.Port.tcp(80),
            'Allow HTTP outbound traffic for SSM',
        );
        // Create VPC endpoints for SSM connectivity
        const ssmEndpoint = new ec2.InterfaceVpcEndpoint(this, 'SSMEndpoint', {
            vpc: this.vpc,
            service: ec2.InterfaceVpcEndpointAwsService.SSM,
            privateDnsEnabled: true,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSecurityGroup],
        });

        const ec2MessagesEndpoint = new ec2.InterfaceVpcEndpoint(this, 'EC2MessagesEndpoint', {
            vpc: this.vpc,
            service: ec2.InterfaceVpcEndpointAwsService.EC2_MESSAGES,
            privateDnsEnabled: true,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSecurityGroup],
        });

        const ssmmessagesEndpoint = new ec2.InterfaceVpcEndpoint(this, 'SSMMessagesEndpoint', {
            vpc: this.vpc,
            service: ec2.InterfaceVpcEndpointAwsService.SSM_MESSAGES,
            privateDnsEnabled: true,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSecurityGroup],
        });

        // S3 Gateway endpoint (more cost-effective than interface endpoint for S3)
        const s3Endpoint = new ec2.GatewayVpcEndpoint(this, 'S3Endpoint', {
            vpc: this.vpc,
            service: ec2.GatewayVpcEndpointAwsService.S3,
        });

        const cloudHSMEndpoint = new ec2.InterfaceVpcEndpoint(this, 'CloudHSMEndpoint', {
            vpc: this.vpc,
            service: new ec2.InterfaceVpcEndpointAwsService('cloudhsm'),
            privateDnsEnabled: true,
            subnets: { subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS },
            securityGroups: [endpointSecurityGroup],
        });

        return {
            ssmEndpoint,
            ec2MessagesEndpoint,
            ssmmessagesEndpoint,
            s3Endpoint,
            cloudHSMEndpoint,
            endpointSecurityGroup,
        };
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

        this.availabilityZonesOutput = new cdk.CfnOutput(this, 'AvailabilityZones', {
            value: this._availabilityZones.join(','),
            description: 'Actual Availability Zones used for VPC deployment',
            exportName: 'CloudHsmAvailabilityZones',
        });

        // Add outputs for VPC endpoints
        new cdk.CfnOutput(this, 'SSMEndpointId', {
            value: this.ssmEndpoint.vpcEndpointId,
            description: 'SSM VPC Endpoint ID',
            exportName: 'CloudHsmSSMEndpointId',
        });

        new cdk.CfnOutput(this, 'EC2MessagesEndpointId', {
            value: this.ec2MessagesEndpoint.vpcEndpointId,
            description: 'EC2 Messages VPC Endpoint ID',
            exportName: 'CloudHsmEC2MessagesEndpointId',
        });

        new cdk.CfnOutput(this, 'SSMMessagesEndpointId', {
            value: this.ssmmessagesEndpoint.vpcEndpointId,
            description: 'SSM Messages VPC Endpoint ID',
            exportName: 'CloudHsmSSMMessagesEndpointId',
        });

        new cdk.CfnOutput(this, 'S3EndpointId', {
            value: this.s3Endpoint.vpcEndpointId,
            description: 'S3 Gateway VPC Endpoint ID',
            exportName: 'CloudHsmS3EndpointId',
        });
    }
}
