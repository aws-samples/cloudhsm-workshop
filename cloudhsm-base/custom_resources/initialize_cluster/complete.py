import logging
import boto3
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

hsm = boto3.client('cloudhsmv2')

def isComplete(event, context):
    
    logger.info(event)
    request_type = event['RequestType']
    props = event['ResourceProperties']


    if request_type == 'Create':
        cluster_id = props['ClusterId']
        resp = hsm.describe_clusters(
            Filters={"clusterIds":[cluster_id]}
        )
        logger.info(resp)
        if (resp['Clusters'][0]['State'] == "INITIALIZED"):
            logger.info("Cluster is ready")

            output = {
                'IsComplete': True
            }
            return output
    else:
        return {'IsComplete': True}
        
    logger.info("Cluster operation not ready yet")      
    return {'IsComplete': False}

