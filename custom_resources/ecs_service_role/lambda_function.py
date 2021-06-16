from __future__ import print_function

import logging
from time import sleep
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

iam_client = boto3.client('iam')


def onCreate(event, context):

    props = event['ResourceProperties']

    role = iam_client.get_role(RoleName='AWSServiceRoleForECS')
    if not role:
        iam_client.create_service_linked_role(AWSServiceName='ecs.amazonaws.com')


    return True

def onDelete(event, context):
    return False

def onUpdate(event, context):
    return False


def handler(event, context):

    logger.info(event)
    request_type = event['RequestType']
  
    if request_type == 'Create' : return onCreate(event,context)
    if request_type == 'Update' : return onUpdate(event,context)
    if request_type == 'Delete' : return onDelete(event,context)

    return False

