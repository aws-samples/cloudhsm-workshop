"""
CloudHSM Available AZs Finder Custom Resource Lambda Function
Created: 2025-01-09
Author: rickardl
Description: Custom Resource for finding available AZs that support CloudHSM, EC2, and ECS
"""

import boto3
import logging
import json
from typing import List, Dict, Any, Set
from botocore.exceptions import BotoCoreError, ClientError
from datetime import datetime, timezone


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
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger_handler = logging.StreamHandler()
logger_handler.setFormatter(JsonFormatter())
logger.handlers = [logger_handler]

# Initialize AWS clients
ec2_client = boto3.client("ec2")
ecs_client = boto3.client("ecs")

# Constants
PHYSICAL_RESOURCE_ID = "CloudHsmAvailableAZs"
SERVICE_REQUIREMENTS = {"CLOUDHSM": "cloudhsmv2", "EC2": "ec2", "ECS": "ecs"}


class InsufficientAZsError(Exception):
    """Custom exception for insufficient AZs."""

    pass


class ServiceNotAvailableError(Exception):
    """Custom exception for service availability issues."""

    pass


def get_cloudhsm_azs(region: str) -> Set[str]:
    """
    Get AZs that support CloudHSM.

    Args:
        region: AWS region to check

    Returns:
        Set of AZ names that support CloudHSM

    Raises:
        ServiceNotAvailableError: If CloudHSM service is not available
        ClientError: If AWS API call fails
    """
    try:
        response = ec2_client.describe_vpc_endpoint_services(
            ServiceNames=[f"com.amazonaws.{region}.cloudhsmv2"]
        )

        logger.info(
            "Retrieved CloudHSM service details",
            extra={
                "props": {
                    "region": region,
                    "service_details": response.get("ServiceDetails", []),
                }
            },
        )

        if not response["ServiceDetails"]:
            raise ServiceNotAvailableError(
                f"CloudHSM service not available in region {region}"
            )

        azs = set(response["ServiceDetails"][0]["AvailabilityZones"])
        logger.info("Found CloudHSM AZs", extra={"props": {"azs": list(azs)}})
        return azs

    except ClientError as e:
        logger.error(
            "Failed to get CloudHSM AZs",
            extra={"props": {"error": str(e), "region": region}},
        )
        raise


def get_ec2_azs(region: str) -> Set[str]:
    """
    Get AZs that support EC2.

    Args:
        region: AWS region to check

    Returns:
        Set of AZ names that support EC2

    Raises:
        ClientError: If AWS API call fails
    """
    try:
        response = ec2_client.describe_availability_zones(
            Filters=[
                {
                    "Name": "opt-in-status",
                    "Values": ["opt-in-not-required", "opted-in"],
                },
                {"Name": "state", "Values": ["available"]},
            ]
        )

        azs = {az["ZoneName"] for az in response["AvailabilityZones"]}
        logger.info("Found EC2 AZs", extra={"props": {"azs": list(azs)}})
        return azs

    except ClientError as e:
        logger.error(
            "Failed to get EC2 AZs",
            extra={"props": {"error": str(e), "region": region}},
        )
        raise


def get_ecs_azs(region: str) -> Set[str]:
    """
    Get AZs that support ECS (currently same as EC2).

    Args:
        region: AWS region to check

    Returns:
        Set of AZ names that support ECS
    """
    return get_ec2_azs(region)


def validate_inputs(props: Dict[str, Any]) -> None:
    """
    Validate the input properties.

    Args:
        props: Dictionary of input properties

    Raises:
        ValueError: If required properties are missing or invalid
    """
    required_props = ["Region", "RequiredNumberOfAZs"]
    missing_props = [prop for prop in required_props if prop not in props]

    if missing_props:
        raise ValueError(f"Missing required properties: {', '.join(missing_props)}")

    try:
        required_azs = int(props["RequiredNumberOfAZs"])
        if required_azs < 1:
            raise ValueError("RequiredNumberOfAZs must be greater than 0")
    except ValueError as e:
        raise ValueError("RequiredNumberOfAZs must be a valid integer") from e


def create_response(azs: List[str]) -> Dict[str, Any]:
    """
    Create a standardized response.

    Args:
        azs: List of available AZs

    Returns:
        Dictionary containing the response data
    """
    response = {
        "PhysicalResourceId": PHYSICAL_RESOURCE_ID,
        "Data": {"AvailableAZs": ",".join(azs), "NumberOfAZs": len(azs)},
    }
    logger.info("Creating response", extra={"props": {"response": response}})
    return response


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler to find available AZs supporting CloudHSM, EC2, and ECS.

    Args:
        event: Lambda event
        context: Lambda context

    Returns:
        Dictionary containing the response data

    Raises:
        Various exceptions based on the error conditions
    """
    logger.info("Processing request", extra={"props": {"event": event}})

    try:
        props = event["ResourceProperties"]
        validate_inputs(props)

        region = props["Region"]
        required_number_of_azs = int(props["RequiredNumberOfAZs"])

        # Get available AZs for each service
        cloudhsm_azs = get_cloudhsm_azs(region)
        ec2_azs = get_ec2_azs(region)
        ecs_azs = get_ecs_azs(region)

        # Find intersection of all AZs
        available_azs = sorted(list(cloudhsm_azs & ec2_azs & ecs_azs))

        logger.info(
            "AZ availability analysis",
            extra={
                "props": {
                    "cloudhsm_azs": list(cloudhsm_azs),
                    "ec2_azs": list(ec2_azs),
                    "ecs_azs": list(ecs_azs),
                    "available_azs": available_azs,
                    "required_azs": required_number_of_azs,
                }
            },
        )

        if len(available_azs) >= required_number_of_azs:
            selected_azs = available_azs[:required_number_of_azs]
            logger.info(
                "Selected AZs",
                extra={
                    "props": {"selected_azs": selected_azs, "count": len(selected_azs)}
                },
            )
            return create_response(selected_azs)
        else:
            raise InsufficientAZsError(
                f"Required {required_number_of_azs} AZs, but only {len(available_azs)} available"
            )

    except (BotoCoreError, ClientError) as e:
        logger.error("AWS API error", extra={"props": {"error": str(e)}})
        raise
    except Exception as e:
        logger.error("Unexpected error", extra={"props": {"error": str(e)}})
        raise
