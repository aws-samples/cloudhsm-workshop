from __future__ import print_function

import logging
from time import sleep
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

hsm_client = boto3.client('cloudhsmv2')


def onCreate(event, context):

    props = event['ResourceProperties']
    clusterId = props['ClusterId']

    resp = hsm_client.describe_clusters(
            Filters={"clusterIds":[clusterId]}
        )
    

    logger.info(resp)
    if (resp['Clusters'][0]['State']!="ACTIVE"):
        return {'IsComplete' : False}

    return {'IsComplete' : True}
    

def onDelete(event, context):
    #Must wait for Cluster to get out of transition state to trigger delete.
    return False    

def onUpdate(event, context):
    return False

def isComplete(event, context):
    
    logger.info(event)
    request_type = event['RequestType']

    if request_type != 'Create':
        return {'IsComplete' : True}

    props = event['ResourceProperties']
    clusterId = props['ClusterId']

    resp = hsm_client.describe_clusters(
            Filters={"clusterIds":[clusterId]}
        )
    logger.info(resp)

    if (resp['Clusters'][0]['State']!="ACTIVE"):
        logger.info('Cluster not Active yet')
        return {'IsComplete' : False}

    return {'IsComplete' : True}


def handler(event, context):

    logger.info(event)
    request_type = event['RequestType']
  
    if request_type == 'Create' : return onCreate(event,context)
    if request_type == 'Update' : return onUpdate(event,context)
    if request_type == 'Delete' : return onDelete(event,context)

    return False


