from __future__ import print_function

import logging
from time import sleep
import boto3
import botocore

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

hsm_client = boto3.client('cloudhsmv2')


def onCreate(event, context):

    props = event['ResourceProperties']
    clusterId = props['ClusterId']

    cluster = hsm_client.describe_clusters(
            Filters={"clusterIds":[clusterId]}
        )
    
    hsmAZ = False
    # Find the next available AZ
    for az,subnet in cluster['Clusters'][0]['SubnetMapping'].items():
        logger.info(az)
        if not cluster['Clusters'][0]['Hsms']:
            hsmAZ = az
            break   # First one is ok
        for hsm in cluster['Clusters'][0]['Hsms']:
            if az == hsm['AvailabilityZone']:
                continue
            else:
                hsmAZ = az
                break
        if hsmAZ != False:
            break

    if hsmAZ == False:
        raise Exception("No more AZ Available")
 
    resp = hsm_client.create_hsm(
        ClusterId=clusterId,
        AvailabilityZone=hsmAZ)
    logger.info(resp)
    output = {
        'PhysicalResourceId': resp['Hsm']['HsmId'],
        'Data' : {
            'HsmId' : resp['Hsm']['HsmId'],
            'AvailableAz' : hsmAZ,
        },
        'IsComplete': False
    }
    
    return output
    

def onDelete(event, context):
    #Must wait for Cluster to get out of transition state to trigger delete.

    hsmId = event['PhysicalResourceId']
    props = event['ResourceProperties']
    clusterId = props['ClusterId'] 
    try:

        resp = hsm_client.delete_hsm(
            HsmId=hsmId,
            ClusterId=clusterId
        )
    except botocore.exceptions.ClientError as error: 
        logger.info("Failed to delete HSM")
        logger.info(error)

    return False    

def onUpdate(event, context):
    return False

def isComplete(event, context):
    
    logger.info(event)
    request_type = event['RequestType']
    props = event['ResourceProperties']
    clusterId = props['ClusterId']
    hsmId = event['PhysicalResourceId']

    resp = hsm_client.describe_clusters(
            Filters={"clusterIds":[clusterId]}
        )
    logger.info(resp)
    
    found = False
    for hsm in resp['Clusters'][0]['Hsms']:
        logger.info('Cheking HSM ' + hsm['HsmId'])
        if hsm['HsmId'] == hsmId:
            found = True
            if request_type == 'Create':
                if (hsm['State'] == "ACTIVE"):
                    logger.info("HSM is ready")

                    output = {
                            'PhysicalResourceId': hsm['HsmId'],
                            'IsComplete': True,
                            'Data': {
                                'HsmId': hsm['HsmId'],
                                'EniIp': hsm['EniIp']
                            }}    
                    return output
            elif request_type == 'Delete':
                logging.info(resp)
                if (hsm['State'] == "DELETED"):
                    logger.info("Cluster deleted")
                    return {'IsComplete': True}
                elif (hsm['State'] == "ACTIVE"):
                    logger.info("Attempting to delete in loop")
                    try:
                        resp = hsm_client.delete_hsm(
                            HsmId=hsm['HsmId'],
                            ClusterId=clusterId
                        )
                    except botocore.exceptions.ClientError as error: 
                        logger.info("Failed to delete HSM in loop")
                        logger.info(error)
                
        
    if not found and (request_type == 'Delete'):
        logger.info("HSM " + hsmId + " was removed")
        return {'IsComplete' : True}

    logger.info("HSM operation not ready yet")      
    return {'IsComplete': False}


def handler(event, context):

    logger.info(event)
    request_type = event['RequestType']
  
    if request_type == 'Create' : return onCreate(event,context)
    if request_type == 'Update' : return onUpdate(event,context)
    if request_type == 'Delete' : return onDelete(event,context)

    return False


