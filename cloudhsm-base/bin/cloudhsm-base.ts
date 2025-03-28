#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { CloudhsmBaseStack } from "../lib/cloudhsm-base-stack";
import { CloudhsmLookupStack } from "../lib/cloudhsm-lookup-stack";
import { EcsTestStack } from "../lib/cloudhsm-ecs-stack";
import { CloudHsmNetworkStack } from "../lib/cloudhsm-network-stack";

const app = new cdk.App();

// Get context values with defaults
const context = {
  expressMode: app.node.tryGetContext("express") === "true" || false,
  requiredAzs: parseInt(app.node.tryGetContext("requiredAzs") || "2"),
  environment: app.node.tryGetContext("environment") || "Development",
  project: app.node.tryGetContext("project") || "CloudHSM-Demo",
  region:
    app.node.tryGetContext("region") ||
    process.env.CDK_DEFAULT_REGION ||
    "ap-northeast-2",
};

// Define the environment
const env = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region: context.region,
};

// For testing, using static AZs if lookup stack is commented out
const availableAZs = app.node
  .tryGetContext("availabilityZones")
  ?.split(",")
  .map((az: string) => az.trim()) || ["ap-northeast-2a", "ap-northeast-2b"];

// Create the CloudhsmNetworkStack
const networkStack = new CloudHsmNetworkStack(app, "CloudhsmNetworkStack", {
  env,
  region: env.region,
  availabilityZones: availableAZs,
  maxAzs: context.requiredAzs,
});

// Create the CloudhsmBaseStack
const cloudHsmStack = new CloudhsmBaseStack(app, "CloudhsmBaseStack", {
  env,
  vpc: networkStack.vpc,
  availabilityZones: networkStack.availabilityZonesOutput.value.split(","),
  expressMode: context.expressMode,
});

// Add dependency
cloudHsmStack.addDependency(networkStack);

// Create the EcsTestStack
const ecsTestStack = new EcsTestStack(app, "EcsTestStack", {
  env,
  vpc: networkStack.vpc,
  clusterSG: cloudHsmStack.clusterSG,
  ec2InstanceSG: cloudHsmStack.ec2InstanceSG,
  clusterIdParam: cloudHsmStack.clusterIdParam,
  selfSignedCert: cloudHsmStack.selfSignedCert,
  cuPassword: cloudHsmStack.cuPassword,
});

// Add dependency
ecsTestStack.addDependency(cloudHsmStack);

// Add tags to all stacks
const tags = {
  Environment: context.environment.replace(/[^a-zA-Z0-9_.:/=+\-@\s]/g, ""),
  Project: context.project.replace(/[^a-zA-Z0-9_.:/=+\-@\s]/g, ""),
};

// Add stack-specific tags
cdk.Tags.of(networkStack).add("Stack", "Network", {
  includeResourceTypes: ["*"],
});
cdk.Tags.of(cloudHsmStack).add("Stack", "CloudHSM", {
  includeResourceTypes: ["*"],
});
cdk.Tags.of(ecsTestStack).add("Stack", "ECS", {
  includeResourceTypes: ["*"],
});

// Add common tags to all stacks
for (const [key, value] of Object.entries(tags)) {
  cdk.Tags.of(app).add(key, value);
}

// Add description to stacks - sanitize the mode text
const mode = context.expressMode ? "Express" : "Standard";
const description = `CloudHSM-Demo-Stack-${mode}-Mode`;
cdk.Tags.of(app).add("Description", description);
