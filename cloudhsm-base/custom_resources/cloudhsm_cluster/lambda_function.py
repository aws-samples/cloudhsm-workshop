from __future__ import print_function
import logging
from typing import Dict, Any
from datetime import datetime, timezone
from time import sleep
import boto3
import json

# Set up logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Custom JSON formatter for structured logging
class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "created_by": "rickardl",
            "created_date": "2025-01-09",
        }
        if hasattr(record, "props"):
            log_record.update(record.props)
        return json.dumps(log_record)


# Configure logger with JSON formatter
handler = logging.StreamHandler()
handler.setFormatter(JsonFormatter())
logger.handlers = [handler]

# Initialize AWS client
hsm_client = boto3.client("cloudhsmv2")


def onCreate(event, context):
    props = event["ResourceProperties"]
    subnets = props["SubnetIds"]

    # Base cluster creation parameters
    cluster_params = {
        "HsmType": "hsm2m.medium",
        "SubnetIds": subnets,
        "BackupRetentionPolicy": {"Type": "DAYS", "Value": "7"},
        "Mode": props.get("Mode", "NON_FIPS"), # FIPS or NON_FIPS, default is NON_FIPS
    }

    # Add SecurityGroupId if provided
    if "SecurityGroupId" in props:
        cluster_params["SecurityGroupId"] = props["SecurityGroupId"]

    resp = hsm_client.create_cluster(**cluster_params)
    logger.info(resp)

    output = {
        "PhysicalResourceId": resp["Cluster"]["ClusterId"],
        "Data": {
            "ClusterId": resp["Cluster"]["ClusterId"],
        },
    }

    return output


def onDelete(event, context):
    clusterId = event["PhysicalResourceId"]
    # delete backups
    backups = hsm_client.describe_backups(
        Filters={"clusterIds": [event["PhysicalResourceId"]]}
    )
    logger.info(backups)

    for backup in backups["Backups"]:
        delete_backup = hsm_client.delete_backup(BackupId=backup["BackupId"])
        logger.info(delete_backup)

    # Check if the cluster is deleted
    cluster = hsm_client.describe_clusters(Filters={"clusterIds": [clusterId]})
    # Check if the cluster exists and is not in a deleting state
    if len(cluster["Clusters"]) > 0 and cluster["Clusters"][0]["State"] != "DELETED":
        delete_cluster = hsm_client.delete_cluster(ClusterId=clusterId)
        logger.info(delete_cluster)
    else:
        logger.info(f"Cluster {clusterId} is already deleted")

    return False


def onUpdate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle Update request.

    Since CloudHSM clusters don't support in-place updates and the cluster
    is already ACTIVE, we should return completion immediately.

    Args:
        event: Lambda event containing the update request
        context: Lambda context

    Returns:
        Dictionary containing the completion status and cluster data
    """
    logger.info(
        "Processing update request",
        extra={
            "props": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "physical_id": event["PhysicalResourceId"],
                "old_props": event["OldResourceProperties"],
                "new_props": event["ResourceProperties"],
            }
        },
    )

    try:
        # Get current cluster state
        cluster = hsm_client.describe_clusters(
            Filters={"clusterIds": [event["PhysicalResourceId"]]}
        )["Clusters"][0]

        # For security group updates, which aren't supported
        if event["OldResourceProperties"].get("SecurityGroupId") != event[
            "ResourceProperties"
        ].get("SecurityGroupId"):
            raise Exception("Cannot update Security Group after cluster creation")

        # Return completion with current cluster data
        return {
            "PhysicalResourceId": cluster["ClusterId"],
            "Data": {
                "ClusterId": cluster["ClusterId"],
                "SecurityGroupId": cluster.get("SecurityGroup"),
                "State": cluster["State"],
                "SubnetMapping": cluster.get("SubnetMapping", {}),
                "VpcId": cluster.get("VpcId"),
                "LastUpdated": datetime.now(timezone.utc).isoformat(),
                "Mode": cluster.get("Mode", "NON_FIPS"),
            },
        }

    except Exception as e:
        logger.error(
            "Update operation failed",
            extra={
                "props": {
                    "error": str(e),
                    "cluster_id": event["PhysicalResourceId"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            },
        )
        raise


def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Check if the operation is complete.

    Created: 2025-01-09 21:17:06 UTC
    Author: rickardl

    Args:
        event: Lambda event containing request details
        context: Lambda context

    Returns:
        Dictionary containing completion status and cluster data
    """
    logger.info(
        "Checking completion status",
        extra={
            "props": {
                "request_type": event["RequestType"],
                "cluster_id": event["PhysicalResourceId"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        },
    )

    request_type = event["RequestType"]
    resp = hsm_client.describe_clusters(
        Filters={"clusterIds": [event["PhysicalResourceId"]]}
    )

    # Handle no clusters found
    if not resp.get("Clusters"):
        if request_type == "Delete":
            logger.info("Cluster is deleted")
            return {"IsComplete": True}
        else:
            logger.error("Cluster not found")
            raise Exception(f"Cluster {event['PhysicalResourceId']} not found")

    cluster = resp["Clusters"][0]
    cluster_state = cluster["State"]

    logger.info(
        "Current cluster state",
        extra={
            "props": {
                "cluster_id": cluster["ClusterId"],
                "state": cluster_state,
                "request_type": request_type,
            }
        },
    )

    if request_type == "Create":
        if cluster_state == "CREATE_IN_PROGRESS":
            return {"IsComplete": False}
        elif cluster_state == "UNINITIALIZED":
            return {
                "IsComplete": True,
                "Data": {
                    "ClusterId": cluster["ClusterId"],
                    "SecurityGroupId": cluster.get("SecurityGroup"),
                    "State": cluster_state,
                    "CreateTimestamp": datetime.now(timezone.utc).isoformat(),
                    "Mode": cluster.get("Mode", "NON_FIPS"),
                },
            }

    elif request_type == "Update":
        if cluster_state == "ACTIVE":
            return {
                "IsComplete": True,
                "Data": {
                    "ClusterId": cluster["ClusterId"],
                    "SecurityGroupId": cluster.get("SecurityGroup"),
                    "State": cluster_state,
                    "SubnetMapping": cluster.get("SubnetMapping", {}),
                    "VpcId": cluster.get("VpcId"),
                    "UpdateTimestamp": datetime.now(timezone.utc).isoformat(),
                    "Mode": cluster.get("Mode", "NON_FIPS"),
                },
            }

    elif request_type == "Delete":
        if cluster_state == "DELETED":
            return {"IsComplete": True}
        elif cluster_state == "DELETE_IN_PROGRESS":
            return {"IsComplete": False}
        elif len(cluster["Hsms"]) == 0:
            hsm_client.delete_cluster(ClusterId=event["PhysicalResourceId"])
            return {"IsComplete": False}

    logger.info(
        "Operation in progress",
        extra={
            "props": {
                "cluster_id": cluster["ClusterId"],
                "state": cluster_state,
                "request_type": request_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        },
    )
    return {"IsComplete": False}


def handler(event, context):
    logger.info(event)
    request_type = event["RequestType"]

    if request_type == "Create":
        return onCreate(event, context)
    if request_type == "Update":
        return onUpdate(event, context)
    if request_type == "Delete":
        return onDelete(event, context)

    return False
