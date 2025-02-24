"""
CloudHSM Cluster Waiter Custom Resource Lambda Function
Created: 2025-01-09
Author: rickardl
Description: Custom Resource for waiting for CloudHSM Cluster to become ACTIVE
"""

from __future__ import print_function
import logging
import boto3
from botocore.exceptions import ClientError
import json
from typing import Dict, Any
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

# Initialize AWS clients
hsm_client = boto3.client('cloudhsmv2')

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
    "DEGRADED": "DEGRADED"
}

def get_cluster(cluster_id: str) -> Dict[str, Any]:
    """Get cluster information with error handling."""
    try:
        response = hsm_client.describe_clusters(
            Filters={"clusterIds": [cluster_id]}
        )
        clusters = response.get("Clusters", [])
        if not clusters:
            raise ValueError(f"No cluster found with ID: {cluster_id}")
        return clusters[0]
    except hsm_client.exceptions.CloudHsmInvalidRequestException as e:
        logger.error("Invalid request", extra={"props": {"error": str(e), "cluster_id": cluster_id}})
        raise
    except hsm_client.exceptions.CloudHsmInternalFailureException as e:
        logger.error("Internal failure", extra={"props": {"error": str(e), "cluster_id": cluster_id}})
        raise
    except ClientError as e:
        logger.error("AWS API error", extra={"props": {"error": str(e), "cluster_id": cluster_id}})
        raise

def onCreate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Create request."""
    props = event["ResourceProperties"]
    cluster_id = props["ClusterId"]

    try:
        cluster = get_cluster(cluster_id)
        cluster_state = cluster["State"]

        logger.info("Checking cluster state", extra={
            "props": {
                "cluster_id": cluster_id,
                "cluster_state": cluster_state,
                "state_message": cluster.get("StateMessage", "")
            }
        })

        if cluster_state != CLUSTER_STATES["ACTIVE"]:
            return {"IsComplete": False}

        return {
            "IsComplete": True,
            "Data": {
                "ClusterId": cluster_id,
                "State": cluster_state,
                "SecurityGroup": cluster.get("SecurityGroup", ""),
                "VpcId": cluster.get("VpcId", ""),
                "SubnetMapping": cluster.get("SubnetMapping", {}),
                "HsmType": cluster.get("HsmType", ""),
                "NetworkType": cluster.get("NetworkType", "IPV4")
            }
        }

    except Exception as e:
        logger.error("Error in onCreate", extra={
            "props": {
                "error": str(e),
                "cluster_id": cluster_id
            }
        })
        raise

def onDelete(event: Dict[str, Any], context: Any) -> bool:
    """Handle Delete request."""
    try:
        props = event["ResourceProperties"]
        cluster_id = props["ClusterId"]

        cluster = get_cluster(cluster_id)
        cluster_state = cluster["State"]

        logger.info("Checking cluster state for deletion", extra={
            "props": {
                "cluster_id": cluster_id,
                "cluster_state": cluster_state
            }
        })

        # Return False while cluster is in a transition state
        if cluster_state.endswith("_IN_PROGRESS"):
            return False

        return True

    except ValueError:
        # If cluster is not found, consider delete successful
        logger.info("Cluster not found, considering delete complete")
        return True
    except Exception as e:
        logger.error("Error in onDelete", extra={"props": {"error": str(e)}})
        raise

def onUpdate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Update request."""
    return {
        "PhysicalResourceId": event.get("PhysicalResourceId"),
        "IsComplete": True
    }

def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Check if the operation is complete."""
    logger.info("Checking completion status", extra={"props": {"event": event}})

    request_type = event.get("RequestType")
    if request_type != "Create":
        return {"IsComplete": True}

    props = event["ResourceProperties"]
    cluster_id = props["ClusterId"]

    try:
        cluster = get_cluster(cluster_id)
        cluster_state = cluster["State"]

        logger.info("Cluster state check", extra={
            "props": {
                "cluster_id": cluster_id,
                "cluster_state": cluster_state,
                "state_message": cluster.get("StateMessage", "")
            }
        })

        if cluster_state != CLUSTER_STATES["ACTIVE"]:
            logger.info("Cluster not Active yet", extra={
                "props": {
                    "current_state": cluster_state,
                    "waiting_for": CLUSTER_STATES["ACTIVE"]
                }
            })
            return {"IsComplete": False}

        return {
            "IsComplete": True,
            "Data": {
                "ClusterId": cluster_id,
                "State": cluster_state,
                "SecurityGroup": cluster.get("SecurityGroup", ""),
                "VpcId": cluster.get("VpcId", ""),
                "SubnetMapping": cluster.get("SubnetMapping", {}),
                "HsmType": cluster.get("HsmType", ""),
                "NetworkType": cluster.get("NetworkType", "IPV4")
            }
        }

    except Exception as e:
        logger.error("Error checking completion status", extra={
            "props": {
                "error": str(e),
                "cluster_id": cluster_id
            }
        })
        raise

def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Main handler function."""
    logger.info("Processing request", extra={"props": {"event": event}})

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
            return {"IsComplete": is_complete}
        else:
            raise ValueError(f"Unsupported request type: {request_type}")

    except Exception as e:
        logger.error("Request failed", extra={
            "props": {
                "error": str(e),
                "event": event
            }
        })
        raise
