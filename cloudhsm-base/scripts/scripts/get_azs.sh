#!/bin/bash

# Add at the top of the script
DEBUG=${DEBUG:-false}

# Set default region and number of AZs if not provided
AWS_REGION=${1:-"us-east-1"}
NUM_AZS=${2:-0}  # 0 means return all AZs
SERVICE_NAME="com.amazonaws.${AWS_REGION}.cloudhsmv2"
OUTPUT_FORMAT="json"

# Function to log messages (to stderr)
log_message() {
    echo "$1" >&2
}

# Function to check if AWS CLI is installed
check_aws_cli() {
    if ! command -v aws &> /dev/null; then
        log_message "ERROR: AWS CLI is not installed"
        exit 1
    fi

    # Check AWS CLI version
    AWS_VERSION=$(aws --version 2>&1 | cut -d/ -f2 | cut -d' ' -f1)
    log_message "Using AWS CLI version: ${AWS_VERSION}"
}

# Function to check if jq is installed
check_jq() {
    if ! command -v jq &> /dev/null; then
        log_message "ERROR: jq is not installed"
        exit 1
    fi
}

# Add debug logging function
debug_log() {
    if [ "${DEBUG}" = "true" ]; then
        log_message "DEBUG: $1"
    fi
}

# Function to check if region is valid
check_region() {
    debug_log "Checking AWS credentials..."
    if ! aws sts get-caller-identity &>/dev/null; then
        log_message "ERROR: AWS credentials not configured"
        exit 1
    fi
    debug_log "AWS credentials verified"

    log_message "Verified region: ${AWS_REGION}"
}

# Function to get available AZs in region
get_available_azs() {
    local region=$1
    local num_azs=$2

    debug_log "Getting available AZs in region: ${region}"

    local az_response=$(aws ec2 describe-availability-zones \
        --region "${region}" \
        --filters "Name=state,Values=available" \
        --query "AvailabilityZones[].ZoneName" \
        --output json)

    if [ $? -ne 0 ] || [ -z "${az_response}" ]; then
        log_message "ERROR: Failed to get availability zones"
        exit 1
    fi

    # If NUM_AZS is specified and greater than 0, limit the output
    if [ "${num_azs}" -gt 0 ]; then
        echo "${az_response}" | jq -c ".[0:${num_azs}]"
    else
        echo "${az_response}"
    fi
}

# Function to get CloudHSM availability zones
get_cloudhsm_azs() {
    local region=$1
    local service_name=$2
    local num_azs=$3

    log_message "Checking CloudHSM availability zones in region: ${region}"

    # Get CloudHSM service details
    local response=$(aws ec2 describe-vpc-endpoint-services \
        --service-names "${service_name}" \
        --region "${region}" \
        --query "ServiceDetails[0].AvailabilityZones" \
        --output json 2>/dev/null)

    if [ $? -ne 0 ] || [ -z "${response}" ] || [ "${response}" == "null" ]; then
        log_message "ERROR: Failed to get CloudHSM service details"
        exit 1
    fi

    # If NUM_AZS is specified and greater than 0, limit the output
    if [ "${num_azs}" -gt 0 ]; then
        echo "${response}" | jq -c ".[0:${num_azs}]"
    else
        echo "${response}"
    fi
}

# Function to get the intersection of AZs
get_az_intersection() {
    local available_azs=$1
    local cloudhsm_azs=$2
    local num_azs=$3

    # Create an intersection of the two arrays
    local intersection=$(jq -n \
        --argjson available "${available_azs}" \
        --argjson cloudhsm "${cloudhsm_azs}" \
        '$available - ($available - $cloudhsm)')

    # If NUM_AZs is specified and greater than 0, limit the output
    if [ "${num_azs}" -gt 0 ]; then
        echo "${intersection}" | jq -c ".[0:${num_azs}]"
    else
        echo "${intersection}"
    fi
}

# Print usage information
usage() {
    echo "Usage: $0 [region] [num_azs]"
    echo "  region  : AWS region (default: us-east-1)"
    echo "  num_azs : Number of AZs to return (default: 0 = all AZs)"
    exit 1
}

# Main execution
main() {
    # Check if help is requested
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        usage
    fi

    log_message "Starting AZ lookup"
    check_aws_cli
    check_jq
    check_region

    log_message "Getting available AZs"
    local available_azs=$(get_available_azs "${AWS_REGION}" "${NUM_AZS}")

    log_message "Getting CloudHSM AZs"
    local cloudhsm_azs=$(get_cloudhsm_azs "${AWS_REGION}" "${SERVICE_NAME}" "${NUM_AZS}")

    log_message "Computing intersection of AZs"
    local intersection_azs=$(get_az_intersection "${available_azs}" "${cloudhsm_azs}" "${NUM_AZS}")

    # Output the final results as a CSV string
    echo "${intersection_azs}" | jq -r 'join(",")'

    log_message "AZ lookup completed"
}

# Execute main function with error handling
{
    main "$@" 2> "az-lookup-${AWS_REGION}.log"
}
