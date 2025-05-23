"""
VPC Endpoint Waiter Custom Resource Lambda Function
Created: 2025-05-18
Description: Custom Resource for waiting for VPC Endpoints to become available
"""

from __future__ import print_function
import logging
import boto3
from botocore.exceptions import ClientError
import json
from typing import Dict, Any, List
from datetime import datetime, timezone
import socket

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
ec2_client = boto3.client('ec2')

# Constants for endpoint states
ENDPOINT_STATES = {
    "PENDING": "pending",
    "AVAILABLE": "available",
    "DELETING": "deleting",
    "DELETED": "deleted",
    "REJECTED": "rejected"
}

def get_vpc_endpoint(endpoint_id: str) -> Dict[str, Any]:
    """Get VPC endpoint information with error handling."""
    try:
        response = ec2_client.describe_vpc_endpoints(
            VpcEndpointIds=[endpoint_id]
        )
        endpoints = response.get("VpcEndpoints", [])
        if not endpoints:
            raise ValueError(f"No VPC endpoint found with ID: {endpoint_id}")
        return endpoints[0]
    except ec2_client.exceptions.InvalidVpcEndpointIdNotFound:
        logger.error("VPC endpoint not found", extra={"props": {"endpoint_id": endpoint_id}})
        raise ValueError(f"No VPC endpoint found with ID: {endpoint_id}")
    except ClientError as e:
        logger.error("AWS API error", extra={"props": {"error": str(e), "endpoint_id": endpoint_id}})
        raise

def check_dns_resolution(dns_name: str) -> bool:
    """Check if DNS name resolves to an IP address using standard socket library."""
    try:
        logger.info("Checking DNS resolution for: %s", dns_name)
        ip_address = socket.gethostbyname(dns_name)
        logger.info("DNS resolved to: %s", ip_address)
        return True
    except socket.gaierror as e:
        logger.warning("DNS resolution failed for %s: %s", dns_name, str(e))
        return False
    except Exception as e:
        logger.warning("Error in DNS resolution for %s: %s", dns_name, str(e))
        return False

def check_port_connectivity(host: str, port: int = 443, timeout: int = 2) -> bool:
    """Check if a TCP connection can be established to the host:port."""
    try:
        logger.info("Testing TCP connection to %s:%s", host, port)
        # Try to get the IP address
        try:
            target_ip = socket.gethostbyname(host)
            logger.info("Resolved %s to IP: %s", host, target_ip)
        except socket.gaierror as e:
            logger.warning("DNS resolution failed for %s: %s", host, str(e))
            return False

        # Then try to connect to the IP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            logger.info("Successfully connected to %s:%s", host, port)
            return True
        else:
            logger.warning("Failed to connect to %s:%s, error code: %s", host, port, result)
            return False
    except Exception as e:
        logger.warning("Connection test failed for %s:%s: %s", host, port, str(e))
        return False

def check_endpoints_ready(endpoint_ids: List[str], region: str) -> Dict[str, Any]:
    """Check if all endpoints are available and their DNS names resolve."""
    all_available = True
    endpoint_statuses = {}
    dns_check_results = {}

    # First check if all endpoints are in available state
    for endpoint_id in endpoint_ids:
        try:
            endpoint = get_vpc_endpoint(endpoint_id)
            endpoint_state = endpoint.get("State", "")
            endpoint_statuses[endpoint_id] = endpoint_state

            if endpoint_state != ENDPOINT_STATES["AVAILABLE"]:
                logger.info("Endpoint %s is not available, state: %s", endpoint_id, endpoint_state)
                all_available = False
        except ValueError:
            logger.warning("Endpoint %s not found", endpoint_id)
            endpoint_statuses[endpoint_id] = "not_found"
            all_available = False

    # If all are available, check DNS resolution for the SSM endpoints
    if all_available:
        ssm_dns_names = [
            f"ssm.{region}.amazonaws.com",
            f"ec2messages.{region}.amazonaws.com",
            f"ssmmessages.{region}.amazonaws.com"
        ]

        for dns_name in ssm_dns_names:
            dns_resolved = check_dns_resolution(dns_name)
            dns_check_results[dns_name] = dns_resolved

            if dns_resolved:
                # Only try port connectivity if DNS resolves
                port_connected = check_port_connectivity(dns_name)
                dns_check_results[f"{dns_name}:443"] = port_connected

                if not port_connected:
                    logger.warning("Port connectivity test failed for %s:443", dns_name)
                    all_available = False
            else:
                logger.warning("DNS resolution failed for %s", dns_name)
                all_available = False

    return {
        "all_ready": all_available,
        "endpoint_statuses": endpoint_statuses,
        "dns_check_results": dns_check_results
    }

def onCreate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Create request."""
    props = event["ResourceProperties"]
    endpoint_ids = props.get("EndpointIds", [])
    region = props.get("Region", "")

    if not endpoint_ids:
        logger.error("No endpoint IDs provided")
        raise ValueError("EndpointIds property is required and must be a non-empty array")

    if not region:
        logger.error("No region provided")
        raise ValueError("Region property is required")

    logger.info("Checking %s VPC endpoints in region %s", len(endpoint_ids), region)
    results = check_endpoints_ready(endpoint_ids, region)

    if not results["all_ready"]:
        logger.info("Not all endpoints are ready", extra={"props": results})
        return {"IsComplete": False}

    logger.info("All VPC endpoints are ready and accessible", extra={"props": results})
    return {
        "IsComplete": True,
        "Data": {
            "EndpointIds": endpoint_ids,
            "EndpointStatuses": results["endpoint_statuses"],
            "DnsCheckResults": results["dns_check_results"]
        }
    }

def onDelete(event: Dict[str, Any], context: Any) -> bool:
    """Handle Delete request."""
    # No need to wait for anything on deletion
    return True

def onUpdate(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handle Update request."""
    # For updates, we need to check if the endpoints are ready just like in creation
    return onCreate(event, context)

def isComplete(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Check if the operation is complete."""
    logger.info("Checking completion status", extra={"props": {"event": event}})

    request_type = event.get("RequestType")
    if request_type == "Delete":
        return {"IsComplete": True}

    return onCreate(event, context)

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
