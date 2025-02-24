"""
CloudHSM Cluster Activation Custom Resource Lambda Function
Created: 2025-01-09 18:41:49
Author: rickardl
Description: Custom Resource for activating CloudHSM clusters via SSM Run Command
"""

from __future__ import print_function
import json
import logging
import boto3
import os
from typing import Dict, Any, Optional, List
from botocore.exceptions import ClientError
from datetime import datetime, timezone
from time import sleep


# Custom JSON formatter for structured logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
        }
        if hasattr(record, "props"):
            log_record.update(record.props)
        return json.dumps(log_record)


# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.StreamHandler()
logger_handler.setFormatter(JsonFormatter())
logger.handlers = [logger_handler]

# Initialize AWS clients
ssm_client = boto3.client("ssm")
s3_client = boto3.client("s3")

# Constants
SSM_TERMINAL_STATES = ["Success", "Failed", "TimedOut", "Cancelled"]
RETRY_INTERVAL = 15  # seconds
TIMEOUT_BUFFER = 20000  # milliseconds


class SSMCommandError(Exception):
    """Custom exception for SSM command failures."""

    pass


def validate_props(props: Dict[str, Any], required_props: List[str]) -> None:
    """Validate required properties are present."""
    missing_props = [prop for prop in required_props if prop not in props]
    if missing_props:
        raise ValueError(f"Missing required properties: {', '.join(missing_props)}")


def send_command(
    instance_id: str, commands: List[str], log_group: str
) -> Optional[Dict[str, Any]]:
    """
    Send SSM command to an instance.

    Args:
        instance_id: EC2 instance ID
        commands: List of commands to execute
        log_group: CloudWatch log group name

    Returns:
        SSM command response or None if failed

    Raises:
        ClientError: If AWS API call fails
    """
    logger.info(
        "Sending SSM command",
        extra={"props": {"instance_id": instance_id, "log_group": log_group}},
    )

    try:
        response = ssm_client.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": commands},
            CloudWatchOutputConfig={
                "CloudWatchOutputEnabled": True,
                "CloudWatchLogGroupName": log_group,
            },
        )

        logger.info(
            "SSM command sent successfully",
            extra={"props": {"command_id": response["Command"]["CommandId"]}},
        )
        return response

    except ssm_client.exceptions.InvalidInstanceId as e:
        logger.error(
            "Invalid instance ID",
            extra={"props": {"instance_id": instance_id, "error": str(e)}},
        )
        return None
    except ClientError as e:
        logger.error("Failed to send SSM command", extra={"props": {"error": str(e)}})
        raise


def create_activation_script(props: Dict[str, Any]) -> str:
    """Create the cluster activation script command."""
    return f"""#!/bin/bash
set -euo pipefail

tempdir=$(mktemp -d)
cd "$tempdir"

aws s3 cp {props['ScriptAssetURL']} ./activate_cluster.sh
chmod +x ./activate_cluster.sh
./activate_cluster.sh \
    {os.environ['AWS_REGION']} \
    {props['SelfSignedParamName']} \
    {props['HSMIpAddress']} \
    {props['ClusterId']} \
    {props['COSecret']} \
    {props['CUSecret']}

cd /
rm -rf "$tempdir"
"""


def onCreate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Create request."""
    logger.info(
        "Processing Create request",
        extra={"props": {"event_id": event.get("RequestId")}},
    )

    props = event["ResourceProperties"]
    required_props = [
        "InstanceId",
        "COSecret",
        "CUSecret",
        "ScriptAssetURL",
        "SelfSignedParamName",
        "HSMIpAddress",
        "LogGroupName",
        "ClusterId",
    ]
    validate_props(props, required_props)

    activation_script = create_activation_script(props)
    return_data = {"Data": {}}

    while True:
        send_response = send_command(
            props["InstanceId"], [activation_script], props["LogGroupName"]
        )

        if send_response:
            command_id = send_response["Command"]["CommandId"]
            return_data.update(
                {"Data": {"CommandId": command_id}, "PhysicalResourceId": command_id}
            )
            break

        if context.get_remaining_time_in_millis() < TIMEOUT_BUFFER:
            logger.error(
                "Command execution timed out",
                extra={
                    "props": {"remaining_time": context.get_remaining_time_in_millis()}
                },
            )
            raise SSMCommandError("Timed out attempting to send command to SSM")

        sleep(RETRY_INTERVAL)

    logger.info(
        "Create request processed", extra={"props": {"return_data": return_data}}
    )
    return return_data


def onIgnore(event: Dict[str, Any], context: Any) -> bool:
    """Handle Update and Delete requests."""
    logger.info(
        "Ignoring request", extra={"props": {"request_type": event["RequestType"]}}
    )
    return False


def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Check if the operation is complete."""
    logger.info(
        "Checking completion status",
        extra={"props": {"event_id": event.get("RequestId")}},
    )

    request_type = event["RequestType"]
    if request_type != "Create":
        return {"IsComplete": True}

    instance_id = event["ResourceProperties"]["InstanceId"]
    command_id = event["Data"]["CommandId"]

    while True:
        try:
            command_status = ssm_client.get_command_invocation(
                CommandId=command_id, InstanceId=instance_id
            )

            status = command_status["Status"]
            logger.info(
                "Command status check",
                extra={
                    "props": {
                        "status": status,
                        "command_id": command_id,
                        "instance_id": instance_id,
                    }
                },
            )

            if status == "Success":
                return {"IsComplete": True}
            elif status in ["Cancelled", "TimedOut", "Failed"]:
                error_message = (
                    command_status.get("StandardErrorContent", "")[:235] or status
                )
                raise SSMCommandError(f"SSM command failed: {error_message}")

            return {"IsComplete": False}

        except ssm_client.exceptions.InvocationDoesNotExist:
            logger.warning(
                "Command invocation not found",
                extra={"props": {"command_id": command_id, "instance_id": instance_id}},
            )

        sleep(RETRY_INTERVAL)


def handler(event: Dict[str, Any], context: Any) -> Any:
    """Main handler function."""
    logger.info(
        "Processing request",
        extra={
            "props": {
                "event_id": event.get("RequestId"),
                "request_type": event.get("RequestType"),
            }
        },
    )

    try:
        request_type = event.get("RequestType")

        if not request_type:
            raise ValueError("Missing RequestType in event")

        if request_type == "Create":
            return onCreate(event, context)
        elif request_type in ["Update", "Delete"]:
            return onIgnore(event, context)
        else:
            raise ValueError(f"Unsupported request type: {request_type}")

    except Exception as e:
        logger.error(
            "Request failed", extra={"props": {"error": str(e), "event": event}}
        )
        raise
