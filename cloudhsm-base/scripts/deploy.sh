#!/bin/bash

# Check required environment variables
if [ -z "${AWS_REGION}" ]; then
    echo "Error: AWS_REGION environment variable is not set"
    exit 1
fi

if [ -z "${CLOUDHSM_EXPRESS}" ]; then
    echo "Error: CLOUDHSM_EXPRESS environment variable is not set"
    exit 1
fi

# Then get the AZs
AZS_CSV=$(./scripts/get_azs.sh "${AWS_REGION}")

if [ -z "${AZS_CSV}" ]; then
    echo "Error: Failed to get availability zones"
    exit 1
fi

# Uncomment this for local development with M1 Mac
#export CDK_DOCKER="./scripts/buildx.sh"  # Using relative path instead

# Run CDK deploy with proper spacing for context parameters
cdk deploy --all \
  --context express="${CLOUDHSM_EXPRESS}" \
  --context availabilityZones="${AZS_CSV}" \
  --region="${AWS_REGION}" \
  --require-approval=never \
  --verbose \
  -O out.json
