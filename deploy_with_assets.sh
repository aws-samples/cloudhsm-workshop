#!/bin/bash
set -e

# Get the region from command line or use default
AWS_REGION=${1:-"us-east-1"}

# Get the AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Set environment variables with region-aware bucket name
export AWS_REGION="${AWS_REGION}"
export CLOUDHSM_EXPRESS='true'
export CDK_DOCKER='./scripts/buildx.sh'  # Enable buildx alias trick for M1 Mac
export CDK_CONTEXT_windows='true'  # Enable Windows Server stack deployment

# Key pair name for Windows EC2 instance
keyPairName="cloudhsm-workshop-keypair"

echo "Environment variables set:"
echo "AWS_REGION = $AWS_REGION"
echo "CLOUDHSM_EXPRESS = $CLOUDHSM_EXPRESS"
echo "CDK_CONTEXT_windows = $CDK_CONTEXT_windows"

# Make sure scripts have correct permissions
chmod +x ./cloudhsm-base/scripts/get_azs.sh
chmod +x ./cloudhsm-base/scripts/deploy.sh

# Change directory to cloudhsm-base and run the deploy script from there
cd "./cloudhsm-base"
echo "Changed directory to $(pwd)"

# Deploy the stacks with CDK
AZS_CSV=$(./scripts/get_azs.sh "${AWS_REGION}")

if [ -z "${AZS_CSV}" ]; then
    echo "Error: Failed to get availability zones"
    exit 1
fi

echo "Using availability zones: ${AZS_CSV}"

set +x

# Removed
#  --context keyPairName="${keyPairName}" \

cdk deploy --all \
  --context express=true \
  --context availabilityZones="${AZS_CSV}" \
  --context assetsBucketName="${ASSETS_BUCKET_NAME}" \
  --context assetsBucketPrefix="${ASSETS_BUCKET_PREFIX}" \
  --context windows=true \
  --context githubUrlPath="aws-samples/cloudhsm-workshop/refs/heads/staging/" \
  --region="${AWS_REGION}" \
  --require-approval never \
  --outputs-file out.json
