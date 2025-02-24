"""
CloudHSM Cluster Initialization Waiter Custom Resource Lambda Function
Created: 2025-01-09 19:09:33
Author: rickardl
Description: Custom Resource for waiting for CloudHSM cluster initialization
"""

import logging
import boto3
from botocore.exceptions import ClientError
import json
from typing import Dict, Any, Optional
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
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger_handler = logging.StreamHandler()
logger_handler.setFormatter(JsonFormatter())
logger.handlers = [logger_handler]

# Initialize AWS client
hsm_client = boto3.client("cloudhsmv2")

# Constants for Cluster states
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


class ClusterNotFoundError(Exception):
    """Custom exception for when a cluster is not found."""

    pass


def get_cluster(cluster_id: str) -> Dict[str, Any]:
    """
    Get cluster information with error handling.

    Args:
        cluster_id: CloudHSM cluster ID

    Returns:
        Dictionary containing cluster information

    Raises:
        ClusterNotFoundError: If the cluster is not found
        ClientError: If AWS API call fails
    """
    try:
        response = hsm_client.describe_clusters(Filters={"clusterIds": [cluster_id]})

        clusters = response.get("Clusters", [])
        if not clusters:
            raise ClusterNotFoundError(f"No cluster found with ID: {cluster_id}")

        logger.info(
            "Retrieved cluster details",
            extra={"props": {"cluster_id": cluster_id, "state": clusters[0]["State"]}},
        )

        return clusters[0]

    except hsm_client.exceptions.CloudHsmInvalidRequestException as e:
        logger.error(
            "Invalid request",
            extra={"props": {"error": str(e), "cluster_id": cluster_id}},
        )
        raise
    except ClientError as e:
        logger.error(
            "AWS API error",
            extra={"props": {"error": str(e), "cluster_id": cluster_id}},
        )
        raise


def validate_props(props: Dict[str, Any]) -> None:
    """Validate the input properties."""
    if "ClusterId" not in props:
        raise ValueError("ClusterId is required in ResourceProperties")


def create_success_response(cluster: Dict[str, Any]) -> Dict[str, Any]:
    """Create response for successful completion."""
    response = {
        "IsComplete": True,
        "Data": {
            "ClusterId": cluster["ClusterId"],
            "ClusterState": cluster["State"],
            "CreateTimestamp": (
                cluster["CreateTimestamp"].isoformat()
                if "CreateTimestamp" in cluster
                else None
            ),
            "SecurityGroup": cluster.get("SecurityGroup", ""),
            "VpcId": cluster.get("VpcId", ""),
            "SubnetMapping": cluster.get("SubnetMapping", {}),
        },
    }

    if "Certificates" in cluster and "ClusterCertificate" in cluster["Certificates"]:
        response["Data"]["ClusterCertificate"] = cluster["Certificates"][
            "ClusterCertificate"
        ]

    return response


def create_in_progress_response() -> Dict[str, Any]:
    """Create response for in-progress state."""
    return {"IsComplete": False}


def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Check if the cluster initialization is complete."""
    logger.info("Checking completion status", extra={"props": {"event": event}})

    try:
        request_type = event.get("RequestType")
        if request_type != "Create":
            logger.info(
                "Non-Create request type",
                extra={"props": {"request_type": request_type}},
            )
            return {"IsComplete": True}

        props = event["ResourceProperties"]
        validate_props(props)

        cluster = get_cluster(props["ClusterId"])
        cluster_state = cluster["State"]

        logger.info(
            "Cluster state check",
            extra={
                "props": {
                    "cluster_id": cluster["ClusterId"],
                    "state": cluster_state,
                    "state_message": cluster.get("StateMessage", ""),
                }
            },
        )

        if cluster_state == CLUSTER_STATES["INITIALIZED"]:
            logger.info("Cluster initialization complete")
            return create_success_response(cluster)
        elif cluster_state in [CLUSTER_STATES["DEGRADED"], CLUSTER_STATES["DELETED"]]:
            raise Exception(f"Cluster in terminal failed state: {cluster_state}")

        logger.info(
            "Cluster initialization in progress",
            extra={
                "props": {
                    "current_state": cluster_state,
                    "waiting_for": CLUSTER_STATES["INITIALIZED"],
                }
            },
        )
        return create_in_progress_response()

    except Exception as e:
        logger.error(
            "Error checking completion status", extra={"props": {"error": str(e)}}
        )
        raise


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main handler function."""
    start_time = datetime.now(timezone.utc)
    logger.info(
        "Processing request",
        extra={"props": {"event": event, "start_time": start_time.isoformat()}},
    )

    try:
        response = isComplete(event, context)
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        logger.info(
            "Request completed",
            extra={
                "props": {
                    "duration_seconds": duration,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                    "is_complete": response.get("IsComplete", False),
                }
            },
        )

        return response

    except Exception as e:
        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        logger.error(
            "Request failed",
            extra={
                "props": {
                    "error": str(e),
                    "duration_seconds": duration,
                    "start_time": start_time.isoformat(),
                    "end_time": end_time.isoformat(),
                }
            },
        )
        raise
