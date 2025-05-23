#!/bin/bash
set -e

# Get the region from command line or use default
AWS_REGION=${1:-"us-east-1"}

# Get the AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

# Set environment variables with region-aware bucket name
export ASSETS_BUCKET_NAME="cloudhsm-workshop-assets-${AWS_ACCOUNT_ID}-${AWS_REGION}"
export ASSETS_BUCKET_PREFIX='cloudhsm-workshop/assets/'
export AWS_REGION="${AWS_REGION}"
export CLOUDHSM_EXPRESS='true'
export CDK_DOCKER='./scripts/buildx.sh'  # Enable buildx alias trick for M1 Mac
export CDK_CONTEXT_windows='true'  # Enable Windows Server stack deployment

# Key pair name for Windows EC2 instance
keyPairName="cloudhsm-workshop-keypair"

echo "Environment variables set:"
echo "ASSETS_BUCKET_NAME = $ASSETS_BUCKET_NAME"
echo "ASSETS_BUCKET_PREFIX = $ASSETS_BUCKET_PREFIX"
echo "AWS_REGION = $AWS_REGION"
echo "CLOUDHSM_EXPRESS = $CLOUDHSM_EXPRESS"
echo "CDK_CONTEXT_windows = $CDK_CONTEXT_windows"

# Create assets bucket if it doesn't exist
echo "Checking if S3 bucket exists: $ASSETS_BUCKET_NAME"
if ! aws s3api head-bucket --bucket $ASSETS_BUCKET_NAME --region $AWS_REGION 2>/dev/null; then
  echo "Creating assets bucket: $ASSETS_BUCKET_NAME in region $AWS_REGION"
  if [ "$AWS_REGION" = "us-east-1" ]; then
    aws s3api create-bucket --bucket $ASSETS_BUCKET_NAME --region $AWS_REGION
  else
    aws s3api create-bucket --bucket $ASSETS_BUCKET_NAME --region $AWS_REGION \
      --create-bucket-configuration LocationConstraint=$AWS_REGION
  fi

  # Add bucket policy to ensure EC2 instances can access it
  echo "Setting bucket policy to allow EC2 instance access..."
  POLICY='{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowEC2Access",
        "Effect": "Allow",
        "Principal": {
          "AWS": "*"
        },
        "Action": [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        "Resource": [
          "arn:aws:s3:::'$ASSETS_BUCKET_NAME'",
          "arn:aws:s3:::'$ASSETS_BUCKET_NAME'/*"
        ],
        "Condition": {
          "StringEquals": {
            "aws:PrincipalAccount": "'$AWS_ACCOUNT_ID'"
          }
        }
      }
    ]
  }'

  echo "$POLICY" > /tmp/bucket_policy.json
  aws s3api put-bucket-policy --bucket $ASSETS_BUCKET_NAME --policy file:///tmp/bucket_policy.json --region $AWS_REGION
else
  echo "Assets bucket already exists: $ASSETS_BUCKET_NAME"
fi

# Upload Windows scripts to S3
echo "Uploading Windows scripts to S3..."
WINDOWS_SCRIPTS_DIR="./cloudhsm-base/scripts/windows"
DEST_PREFIX="${ASSETS_BUCKET_PREFIX}scripts/windows/"

if [ -d "$WINDOWS_SCRIPTS_DIR" ]; then
  for script in "$WINDOWS_SCRIPTS_DIR"/*; do
    if [ -f "$script" ]; then
      script_name=$(basename "$script")
      echo "Uploading $script_name to s3://$ASSETS_BUCKET_NAME/$DEST_PREFIX"
      aws s3 cp "$script" "s3://$ASSETS_BUCKET_NAME/$DEST_PREFIX$script_name" --region $AWS_REGION
    fi
  done
  echo "All Windows scripts uploaded successfully."
else
  echo "Windows scripts directory not found: $WINDOWS_SCRIPTS_DIR"
  exit 1
fi

# Check if key pair exists, if not create it
echo "Checking EC2 key pair: $keyPairName"
if aws ec2 describe-key-pairs --key-names $keyPairName --region $AWS_REGION 2>&1 | grep -q "not found"; then
  echo "Creating key pair: $keyPairName"
  keyPairOutput=$(aws ec2 create-key-pair --key-name $keyPairName --region $AWS_REGION --query "KeyMaterial" --output text)

  if [ -n "$keyPairOutput" ]; then
    # Save to .pem file
    keyDir="$HOME/.ssh"
    mkdir -p "$keyDir"

    keyPath="$keyDir/$keyPairName.pem"
    echo "$keyPairOutput" > "$keyPath"

    # Set proper permissions
    chmod 600 "$keyPath"

    echo "Key pair saved to $keyPath"
  else
    echo "Failed to create key pair. Will continue without it."
  fi
else
  echo "Key pair '$keyPairName' already exists in AWS."
fi

# Set key pair name in CDK context
export CDK_CONTEXT_keyPairName="$keyPairName"
echo "Using key pair: $keyPairName"

# Make sure scripts have correct permissions
chmod +x ./cloudhsm-base/scripts/get_azs.sh
chmod +x ./cloudhsm-base/scripts/deploy.sh

# Change directory to cloudhsm-base and run the deploy script from there
cd "./cloudhsm-base"
echo "Changed directory to $(pwd)"

# Run the deploy script
echo "Using custom asset bucket: $ASSETS_BUCKET_NAME"
echo "With asset prefix: $ASSETS_BUCKET_PREFIX"
echo "Windows Server deployment enabled: $CDK_CONTEXT_windows"
echo "Using Windows key pair: $keyPairName"

# Deploy the stacks with CDK
AZS_CSV=$(./scripts/get_azs.sh "${AWS_REGION}")

if [ -z "${AZS_CSV}" ]; then
    echo "Error: Failed to get availability zones"
    exit 1
fi

echo "Using availability zones: ${AZS_CSV}"

cdk deploy --all \
  --context express=true \
  --context availabilityZones="${AZS_CSV}" \
  --context assetsBucketName="${ASSETS_BUCKET_NAME}" \
  --context assetsBucketPrefix="${ASSETS_BUCKET_PREFIX}" \
  --context windows=true \
  --context keyPairName="${keyPairName}" \
  --region="${AWS_REGION}" \
  --require-approval never \
  --outputs-file out.json
