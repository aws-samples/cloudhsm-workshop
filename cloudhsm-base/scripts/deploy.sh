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

# Optional asset bucket parameters
ASSETS_BUCKET_PARAMS=""
if [ -n "${ASSETS_BUCKET_NAME}" ]; then
  ASSETS_BUCKET_PARAMS="${ASSETS_BUCKET_PARAMS} --context assetsBucketName=${ASSETS_BUCKET_NAME}"
  echo "Using custom asset bucket: ${ASSETS_BUCKET_NAME}"
fi

if [ -n "${ASSETS_BUCKET_PREFIX}" ]; then
  # Note: Trailing slashes are handled in the CDK app
  ASSETS_BUCKET_PARAMS="${ASSETS_BUCKET_PARAMS} --context assetsBucketPrefix=${ASSETS_BUCKET_PREFIX}"
  echo "With asset prefix: ${ASSETS_BUCKET_PREFIX}"
fi

# Check if Windows Server deployment is enabled
WINDOWS_PARAMS=""
if [ -n "${CDK_CONTEXT_windows}" ]; then
  WINDOWS_PARAMS="--context windows=${CDK_CONTEXT_windows}"
  echo "Windows Server deployment enabled: ${CDK_CONTEXT_windows}"

  # Add key pair if specified
  if [ -n "${CDK_CONTEXT_keyPairName}" ]; then
    WINDOWS_PARAMS="${WINDOWS_PARAMS} --context keyPairName=${CDK_CONTEXT_keyPairName}"
    echo "Using Windows key pair: ${CDK_CONTEXT_keyPairName}"
  fi
fi

# Run CDK deploy with proper spacing for context parameters
cdk deploy --all \
  --context express="${CLOUDHSM_EXPRESS}" \
  --context availabilityZones="${AZS_CSV}" \
  --region="${AWS_REGION}" \
  ${ASSETS_BUCKET_PARAMS} \
  ${WINDOWS_PARAMS} \
  --require-approval=never \
  --verbose \
  -O out.json
