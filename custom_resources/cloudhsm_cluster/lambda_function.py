from __future__ import print_function

import logging
from time import sleep
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

hsm_client = boto3.client('cloudhsmv2')


def onCreate(event, context):

    props = event['ResourceProperties']
    subnets = props['SubnetIds']
    resp = hsm_client.create_cluster(
                HsmType="hsm1.medium",
                SubnetIds=subnets,
                BackupRetentionPolicy={"Type":"DAYS", "Value":"7"})
    logger.info(resp)
    output = {
        'PhysicalResourceId': resp['Cluster']['ClusterId'],
        'Data': {
            'ClusterId': resp['Cluster']['ClusterId']
        }
    }
    return output

def onDelete(event, context):


    clusterId = event['PhysicalResourceId']
    # delete backups
    backups = hsm_client.describe_backups(
        Filters={"clusterIds":[event['PhysicalResourceId']]}
    )
    logger.info(backups)

    for backup in backups['Backups']:
        delete_backup = hsm_client.delete_backup(BackupId=backup['BackupId'])
        logger.info(delete_backup)


    return False    

def onUpdate(event, context):
    return False

def isComplete(event, context):
    
    logger.info(event)
    request_type = event['RequestType']
    resp = hsm_client.describe_clusters(
            Filters={"clusterIds":[event['PhysicalResourceId']]}
        )
    logger.info(resp)


    if request_type == 'Create':
        if (resp['Clusters'][0]['State'] == "UNINITIALIZED"):
            logger.info("Cluster is ready")

            output = {
                'IsComplete': True,
                'Data': {
                    'ClusterId': resp['Clusters'][0]['ClusterId'],
                    'SecurityGroupId': resp['Clusters'][0]['SecurityGroup'] 
                }
            }
            return output
    elif request_type == 'Delete':
        #Check if all HSMs were removed before deleting

        logging.info(resp)
        if (resp['Clusters'][0]['State'] != "DELETE_IN_PROGRESS") and (resp['Clusters'][0]['State'] != "DELETED") and (len(resp['Clusters'][0]['Hsms']) == 0):
            resp = hsm_client.delete_cluster(
            ClusterId=event['PhysicalResourceId']
            )
            logging.info(resp)
        elif (resp['Clusters'][0]['State'] == "DELETED"):
            logger.info("Cluster deleted")
            return {'IsComplete': True}
        
    logger.info("Cluster operation not ready yet")      
    return {'IsComplete': False}


def handler(event, context):

    logger.info(event)
    request_type = event['RequestType']
  
    if request_type == 'Create' : return onCreate(event,context)
    if request_type == 'Update' : return onUpdate(event,context)
    if request_type == 'Delete' : return onDelete(event,context)

    return False

