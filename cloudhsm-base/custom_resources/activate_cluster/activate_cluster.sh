#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# Script metadata
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2025-01-09"
SCRIPT_AUTHOR="riclof"

# Parse arguments
region="$1"
self_signed_param="$2"
hsm_ip="$3"
cluster_id="$4"
co_secret_name="$5"
cu_secret_name="$6"

# Constants
CLOUDHSM_DIR="/opt/cloudhsm"
SCRIPT_START_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
WORK_DIR=$(mktemp -d)

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    echo "{\"timestamp\":\"${timestamp}\",\"level\":\"${level}\",\"message\":\"${message}\",\"script_version\":\"${SCRIPT_VERSION}\",\"author\":\"${SCRIPT_AUTHOR}\"}"
}

# Error handling function
error_handler() {
    local line_no="$1"
    log "ERROR" "Error occurred in script at line: ${line_no}"
    cleanup
    exit 1
}

trap 'error_handler ${LINENO}' ERR

# Cleanup function
cleanup() {
    log "INFO" "Performing cleanup..."
    rm -rf "${WORK_DIR}"
}

# Create working directory
mkdir -p "${WORK_DIR}"
cd "${WORK_DIR}" || exit 1

# OS Detection function
detect_os() {
    log "INFO" "Detecting OS and architecture..."
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME=$NAME
        OS_VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS_NAME=$(lsb_release -si)
        OS_VERSION=$(lsb_release -sr)
    else
        OS_NAME=$(uname -s)
        OS_VERSION=$(uname -r)
    fi
    ARCH=$(uname -m)
    log "INFO" "Detected OS: ${OS_NAME}, Version: ${OS_VERSION}, Architecture: ${ARCH}"
}

# Retry function
retry() {
    local n=1
    local max=10
    local delay=5
    while true; do
        "$@" && break || {
            if [[ $n -lt $max ]]; then
                ((n++))
                log "WARN" "Command failed. Attempt $n/$max:"
                sleep $delay;
            else
                log "ERROR" "The command has failed after $n attempts."
                return 1
            fi
        }
    done
}

# Package installation function
install_packages() {
    log "INFO" "Installing CloudHSM client and dependencies..."
    case "$OS_NAME" in
        "Ubuntu"*)
            export DEBIAN_FRONTEND=noninteractive
            sudo apt-get update
            sudo apt-get install -y wget jq awscli
            DEB_PATH="CloudHsmClient/Jammy/cloudhsm-cli_latest_u${OS_VERSION%%.*}.04_${ARCH}.deb"
            wget -q "https://s3.amazonaws.com/cloudhsmv2-software/${DEB_PATH}" -O cloudhsm-client.deb
            sudo dpkg -i ./cloudhsm-client.deb
            rm -f cloudhsm-client.deb
            ;;
        "Amazon Linux"*)
            if [[ "$OS_VERSION" == "2023"* ]]; then
                sudo dnf install -y wget jq awscli
                RPM_PATH="CloudHsmClient/Amzn2023/cloudhsm-cli-latest.amzn2023.${ARCH}.rpm"
                wget -q "https://s3.amazonaws.com/cloudhsmv2-software/${RPM_PATH}" -O cloudhsm-client.rpm
                sudo dnf install -y ./cloudhsm-client.rpm
                rm -f cloudhsm-client.rpm
            else
                sudo yum install -y wget jq awscli
                RPM_PATH="CloudHsmClient/EL7/cloudhsm-cli-latest.el7.${ARCH}.rpm"
                wget -q "https://s3.amazonaws.com/cloudhsmv2-software/${RPM_PATH}" -O cloudhsm-client.rpm
                sudo yum install -y ./cloudhsm-client.rpm
                rm -f cloudhsm-client.rpm
            fi
            ;;
        *)
            log "ERROR" "Unsupported OS: $OS_NAME"
            exit 1
            ;;
    esac
    log "INFO" "Package installation completed"
}

# CloudHSM configuration function
configure_cloudhsm() {
    log "INFO" "Configuring CloudHSM..."
    aws --region "${region}" ssm get-parameter \
        --name "${self_signed_param}" \
        --query Parameter.Value \
        --output text > customerCA.crt

    sudo mv customerCA.crt "${CLOUDHSM_DIR}/etc/customerCA.crt"
    log "INFO" "CloudHSM configuration completed"
}

# Credential retrieval function
retrieve_credentials() {
    log "INFO" "Retrieving credentials from Secrets Manager..."
    COPASSWORD=$(aws --region "${region}" secretsmanager get-secret-value \
        --secret-id "${co_secret_name}" \
        --query SecretString \
        --output text | jq -r '.password')
    CUPASSWORD=$(aws --region "${region}" secretsmanager get-secret-value \
        --secret-id "${cu_secret_name}" \
        --query SecretString \
        --output text | jq -r '.password')
    COUSERNAME=$(aws --region "${region}" secretsmanager get-secret-value \
        --secret-id "${co_secret_name}" \
        --query SecretString \
        --output text | jq -r '.username')
    CUUSERNAME=$(aws --region "${region}" secretsmanager get-secret-value \
        --secret-id "${cu_secret_name}" \
        --query SecretString \
        --output text | jq -r '.username')
    log "INFO" "Credentials retrieved successfully"
}

# Environment variable setup function
set_environment_variables() {
    log "INFO" "Setting up environment variables..."
    export CLOUDHSM_ROLE=admin
    export CLOUDHSM_PIN="${COUSERNAME}:${COPASSWORD}"

    # Verify environment variables
    if [[ -z "${CLOUDHSM_PIN}" ]]; then
        log "ERROR" "CLOUDHSM_PIN environment variable is not set"
        return 1
    fi

    if [[ -z "${CLOUDHSM_ROLE}" ]]; then
        log "ERROR" "CLOUDHSM_ROLE environment variable is not set"
        return 1
    fi

    log "INFO" "Environment variables set successfully"
    return 0
}

# Client configuration function
add_cluster_to_client() {
    log "INFO" "Adding cluster to CloudHSM client..."
    sudo "${CLOUDHSM_DIR}/bin/configure-cli" --cluster-id "${cluster_id}"
    log "INFO" "Cluster added to client successfully"
}

# Cluster activation and user creation function
activate_cluster_and_create_user() {
    log "INFO" "Starting cluster activation and user creation..."

    # Verify environment variables
    if ! set_environment_variables; then
        log "ERROR" "Failed to set required environment variables"
        exit 1
    fi

    # Debug output
    log "DEBUG" "Using CLOUDHSM_ROLE: ${CLOUDHSM_ROLE}"
    log "DEBUG" "CLOUDHSM_PIN is set: $(if [[ -n "${CLOUDHSM_PIN}" ]]; then echo "Yes"; else echo "No"; fi)"

    # Activate cluster
    log "INFO" "Activating cluster..."
    activation_result=$(retry sudo -E "${CLOUDHSM_DIR}/bin/cloudhsm-cli" cluster activate \
        --cluster-id "${cluster_id}" \
        --password "${COPASSWORD}")

    error_code=$(echo "${activation_result}" | jq -r '.error_code')
    error_message=$(echo "${activation_result}" | jq -r '.data')

    if [ "$error_code" -eq 1 ] && [ "$error_message" = "Cluster has already been activated" ]; then
        log "INFO" "Cluster is already activated"
    elif [ "$error_code" -eq 0 ]; then
        log "INFO" "Cluster activated successfully"
    else
        log "ERROR" "Cluster activation failed: ${activation_result}"
        exit 1
    fi

    # Create crypto user
    log "INFO" "Creating crypto user..."
    create_user_result=$(sudo -E "${CLOUDHSM_DIR}/bin/cloudhsm-cli" user create \
        --username "${CUUSERNAME}" \
        --password "${CUPASSWORD}" \
        --role crypto-user)

    user_error_code=$(echo "${create_user_result}" | jq -r '.error_code')
    user_error_message=$(echo "${create_user_result}" | jq -r '.data')

    if [ "$user_error_code" -eq 0 ]; then
        log "INFO" "Crypto user created successfully"
    elif [ "$user_error_code" -eq 1 ] && [[ "$user_error_message" == *"User already exists"* ]]; then
        log "INFO" "Crypto user already exists"
    else
        log "ERROR" "Failed to create crypto user: ${create_user_result}"
        exit 1
    fi
}

# Main function
main() {
    local exit_code=0
    log "INFO" "Starting CloudHSM activation script (Version: ${SCRIPT_VERSION})"

    detect_os || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "OS detection failed"
        exit $exit_code
    fi

    install_packages || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Package installation failed"
        exit $exit_code
    fi

    configure_cloudhsm || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "CloudHSM configuration failed"
        exit $exit_code
    fi

    retrieve_credentials || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Credential retrieval failed"
        exit $exit_code
    fi

    set_environment_variables || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Environment variable setup failed"
        exit $exit_code
    fi

    add_cluster_to_client || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Failed to add cluster to client"
        exit $exit_code
    fi

    activate_cluster_and_create_user || exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log "ERROR" "Cluster activation or user creation failed"
        exit $exit_code
    fi

    cleanup
    SCRIPT_END_TIME=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
    log "INFO" "CloudHSM setup completed successfully"
    log "INFO" "Script execution time: ${SCRIPT_START_TIME} to ${SCRIPT_END_TIME}"
}

# Run main function
main
