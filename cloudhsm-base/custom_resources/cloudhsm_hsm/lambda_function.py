"""
CloudHSM HSM Custom Resource Lambda Function
Created: 2025-01-09
Author: rickardl
Description: Custom Resource for managing CloudHSM HSMs in AWS CloudFormation
"""

from __future__ import print_function
import logging
import boto3
from botocore.exceptions import ClientError
import json
from typing import Dict, Any, List, Set, Optional
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
hsm_client = boto3.client("cloudhsmv2")

# Constants for HSM and Cluster states
HSM_STATES = {
    "CREATE_IN_PROGRESS": "CREATE_IN_PROGRESS",
    "ACTIVE": "ACTIVE",
    "DEGRADED": "DEGRADED",
    "DELETE_IN_PROGRESS": "DELETE_IN_PROGRESS",
    "DELETED": "DELETED",
}

CLUSTER_STATES = {
    "CREATE_IN_PROGRESS": "CREATE_IN_PROGRESS",
    "UNINITIALIZED": "UNINITIALIZED",
    "INITIALIZE_IN_PROGRESS": "INITIALIZE_IN_PROGRESS",
    "INITIALIZED": "INITIALIZED",
    "ACTIVE": "ACTIVE",
    "UPDATE_IN_PROGRESS": "UPDATE_IN_PROGRESS",
    "MODIFY_IN_PROGRESS": "MODIFY_IN_PROGRESS",
    "ROLLBACK_IN_PROGRESS": "ROLLBACK_IN_PROGRESS",
    "DELETE_IN_PROGRESS": "DELETE_IN_PROGRESS",
    "DELETED": "DELETED",
    "DEGRADED": "DEGRADED",
}


def validate_props(props: Dict[str, Any], required_props: List[str]) -> None:
    """Validate that all required properties are present."""
    missing_props = [prop for prop in required_props if prop not in props]
    if missing_props:
        raise ValueError(f"Missing required properties: {', '.join(missing_props)}")


def get_cluster(cluster_id: str) -> Dict[str, Any]:
    """Get cluster information with error handling."""
    try:
        response = hsm_client.describe_clusters(Filters={"clusterIds": [cluster_id]})
        clusters = response.get("Clusters", [])
        if not clusters:
            raise ValueError(f"No cluster found with ID: {cluster_id}")
        return clusters[0]
    except hsm_client.exceptions.CloudHsmInvalidRequestException as e:
        logger.error(
            "Invalid request",
            extra={"props": {"error": str(e), "cluster_id": cluster_id}},
        )
        raise
    except hsm_client.exceptions.CloudHsmInternalFailureException as e:
        logger.error(
            "Internal failure",
            extra={"props": {"error": str(e), "cluster_id": cluster_id}},
        )
        raise
    except ClientError as e:
        logger.error(
            "AWS API error",
            extra={"props": {"error": str(e), "cluster_id": cluster_id}},
        )
        raise


def get_available_azs(cluster: Dict[str, Any], available_azs: List[str]) -> Set[str]:
    """Get available Availability Zones for new HSM deployment."""
    current_hsm_azs = {hsm["AvailabilityZone"] for hsm in cluster["Hsms"]}
    available_subnet_azs = set(cluster["SubnetMapping"].keys())
    potential_azs = set(available_azs) & available_subnet_azs - current_hsm_azs

    logger.info(
        "AZ analysis",
        extra={
            "props": {
                "available_azs": list(available_azs),
                "current_hsm_azs": list(current_hsm_azs),
                "subnet_mapping": cluster["SubnetMapping"],
                "potential_azs": list(potential_azs),
            }
        },
    )

    if not potential_azs:
        raise ValueError(
            f"No available AZs found. Available AZs: {available_azs}, "
            f"Subnet AZs: {available_subnet_azs}, Current HSM AZs: {current_hsm_azs}"
        )
    return potential_azs


def create_hsm(cluster_id: str, az: str) -> str:
    """Create a new HSM in the specified AZ."""
    try:
        logger.info(
            "Creating HSM", extra={"props": {"az": az, "cluster_id": cluster_id}}
        )
        response = hsm_client.create_hsm(ClusterId=cluster_id, AvailabilityZone=az)
        hsm_id = response["Hsm"]["HsmId"]
        logger.info(
            "HSM created", extra={"props": {"hsm_id": hsm_id, "response": response}}
        )
        return hsm_id
    except ClientError as e:
        logger.error("Failed to create HSM", extra={"props": {"error": str(e)}})
        raise


def onCreate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Create request."""
    props = event["ResourceProperties"]
    validate_props(props, ["ClusterId", "AvailabilityZones"])

    cluster_id = props["ClusterId"]
    az_input = props.get("AvailabilityZones")

    if not az_input:
        raise ValueError("AvailabilityZones property is missing or empty")

    available_azs = az_input.split(",")
    if not available_azs:
        raise ValueError("No valid Availability Zones provided")

    cluster = get_cluster(cluster_id)
    potential_azs = get_available_azs(cluster, available_azs)
    selected_az = next(iter(potential_azs))

    hsm_id = create_hsm(cluster_id, selected_az)

    return {
        "PhysicalResourceId": hsm_id,
        "Data": {
            "HsmId": hsm_id,
            "AvailabilityZone": selected_az,
            "ClusterId": cluster_id,
        },
        "IsComplete": False,
    }


def onDelete(event: Dict[str, Any], context: Any) -> bool:
    """Handle Delete request."""
    hsm_id = event["PhysicalResourceId"]
    cluster_id = event["ResourceProperties"]["ClusterId"]

    try:
        cluster = get_cluster(cluster_id)
    except ValueError:
        logger.info(
            "Cluster not found, assuming deleted",
            extra={"props": {"cluster_id": cluster_id}},
        )
        return True

    for hsm in cluster["Hsms"]:
        if hsm["HsmId"] == hsm_id:
            if hsm["State"] == HSM_STATES["ACTIVE"]:
                try:
                    hsm_client.delete_hsm(ClusterId=cluster_id, HsmId=hsm_id)
                    logger.info(
                        "Initiated HSM deletion", extra={"props": {"hsm_id": hsm_id}}
                    )
                except ClientError as e:
                    logger.error(
                        "Failed to delete HSM", extra={"props": {"error": str(e)}}
                    )
                    raise
            return False
    return True


def onUpdate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Update request."""
    return {"PhysicalResourceId": event["PhysicalResourceId"], "IsComplete": True}


def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Check if the operation is complete."""
    logger.info("Checking completion status", extra={"props": {"event": event}})

    request_type = event.get("RequestType")
    resource_properties = event.get("ResourceProperties", {})
    cluster_id = resource_properties.get("ClusterId")
    physical_id = event.get("PhysicalResourceId")

    try:
        cluster = get_cluster(cluster_id)
        cluster_state = cluster.get("State")

        logger.info(
            "Cluster state",
            extra={
                "props": {
                    "cluster_id": cluster_id,
                    "cluster_state": cluster_state,
                    "hsms": cluster.get("Hsms", []),
                }
            },
        )

        if request_type == "Create":
            for hsm in cluster["Hsms"]:
                if hsm["HsmId"] == physical_id:
                    hsm_state = hsm["State"]
                    logger.info(
                        "HSM state check",
                        extra={
                            "props": {
                                "hsm_id": physical_id,
                                "hsm_state": hsm_state,
                                "cluster_state": cluster_state,
                                "state_message": hsm.get("StateMessage", ""),
                            }
                        },
                    )

                    if hsm_state == HSM_STATES["ACTIVE"]:
                        return {
                            "IsComplete": True,
                            "Data": {
                                "HsmId": physical_id,
                                "EniIp": hsm["EniIp"],
                                "EniIpV6": hsm.get("EniIpV6", ""),
                                "State": hsm_state,
                                "StateMessage": hsm.get("StateMessage", ""),
                                "ClusterState": cluster_state,
                                "AvailabilityZone": hsm["AvailabilityZone"],
                                "ClusterId": cluster_id,
                                "SubnetId": hsm["SubnetId"],
                                "EniId": hsm["EniId"],
                                "HsmType": hsm.get("HsmType", ""),
                                "NetworkType": cluster.get("NetworkType", "IPV4"),
                            },
                        }
                    elif hsm_state in [HSM_STATES["DEGRADED"], HSM_STATES["DELETED"]]:
                        raise ValueError(f"HSM in terminal failed state: {hsm_state}")
                    elif hsm_state == HSM_STATES["DELETE_IN_PROGRESS"]:
                        raise ValueError("HSM is being deleted")

                    return {"IsComplete": False}

            logger.info(
                "HSM not found in cluster",
                extra={
                    "props": {
                        "physical_id": physical_id,
                        "cluster_state": cluster_state,
                    }
                },
            )
            return {"IsComplete": False}

        elif request_type == "Delete":
            hsm_exists = any(hsm["HsmId"] == physical_id for hsm in cluster["Hsms"])
            if not hsm_exists:
                logger.info(
                    "HSM deleted successfully", extra={"props": {"hsm_id": physical_id}}
                )
                return {"IsComplete": True}

            for hsm in cluster["Hsms"]:
                if hsm["HsmId"] == physical_id:
                    logger.info(
                        "HSM deletion status",
                        extra={
                            "props": {
                                "hsm_id": physical_id,
                                "state": hsm["State"],
                                "state_message": hsm.get("StateMessage", ""),
                            }
                        },
                    )

            return {"IsComplete": False}

        elif request_type == "Update":
            logger.info("Update operation - no changes required")
            return {"IsComplete": True}

        return {"IsComplete": False}

    except Exception as e:
        logger.error(
            "Error checking completion status",
            extra={
                "props": {
                    "error": str(e),
                    "cluster_id": cluster_id,
                    "physical_id": physical_id,
                    "request_type": request_type,
                }
            },
        )
        if request_type == "Delete":
            return {"IsComplete": True}
        raise


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main handler function."""
    logger.info("Processing request", extra={"props": {"event": event}})

    physical_id = event.get("PhysicalResourceId", "NOT_SET")

    try:
        request_type = event.get("RequestType")

        if not request_type:
            raise ValueError("Missing RequestType in event")

        if request_type == "Create":
            return onCreate(event, context)
        elif request_type == "Update":
            return onUpdate(event, context)
        elif request_type == "Delete":
            is_complete = onDelete(event, context)
            return {"PhysicalResourceId": physical_id, "IsComplete": is_complete}
        else:
            raise ValueError(f"Unsupported request type: {request_type}")

    except Exception as e:
        logger.error(
            "Request failed", extra={"props": {"error": str(e), "event": event}}
        )
        return {
            "Status": "FAILED",
            "Reason": str(e),
            "PhysicalResourceId": physical_id,
        }
