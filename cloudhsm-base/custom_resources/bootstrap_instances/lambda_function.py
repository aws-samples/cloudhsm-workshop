from __future__ import print_function

import logging
from time import sleep
import boto3
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ssm = boto3.client('ssm')


def send_command(instances, commands, log_group):
    logger.debug("Sending command to %s : %s" % (instances, commands))
    try:
        return ssm.send_command(InstanceIds=[instances], DocumentName='AWS-RunShellScript', Parameters={'commands': commands}, CloudWatchOutputConfig= { 'CloudWatchOutputEnabled':True, 'CloudWatchLogGroupName':log_group})
    except ssm.exceptions.InvalidInstanceId:
        logger.debug("Failed to execute SSM command", exc_info=True)
        return


def onChange(event, context):

    props = event['ResourceProperties']
    instanceId = props['InstanceId']
    self_signed_param = props['SelfSignedParamName']
    region = os.environ['AWS_REGION']
    hsm_ip = props['HSMIpAddress']
    log_group = props['LogGroupName']
    os_type = props['OSType']

    # This will work only for AL2
    commands = ['mkdir -p /tmp/setup', 'cd /tmp/setup', 
            'wget -q https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/EL7/cloudhsm-client-latest.el7.x86_64.rpm',
            'sudo yum install -y ./cloudhsm-client-latest.el7.x86_64.rpm',
            'sudo rm -f cloudhsm-client-latest.el7.x86_64.rpm',
            'aws --region ' + region + ' ssm get-parameter --name \'' + self_signed_param + '\' --query Parameter.Value --output text > customerCA.crt',
            'sudo mv customerCA.crt /opt/cloudhsm/etc/customerCA.crt',
            'sudo /opt/cloudhsm/bin/configure -a ' + hsm_ip,
            'sudo /opt/cloudhsm/bin/configure --cmu ' + hsm_ip,
            ]

    if os_type == 'Ubuntu':
        commands = ['mkdir -p /tmp/setup', 'cd /tmp/setup', 
                'wget https://s3.amazonaws.com/cloudhsmv2-software/CloudHsmClient/Bionic/cloudhsm-client_latest_u18.04_amd64.deb',
                'sudo apt install -y ./cloudhsm-client_latest_u18.04_amd64.deb',
                'sudo rm -f cloudhsm-client_latest_u18.04_amd64.deb',
                'aws --region ' + region + ' ssm get-parameter --name \'' + self_signed_param + '\' --query Parameter.Value --output text > customerCA.crt',
                'sudo mv customerCA.crt /opt/cloudhsm/etc/customerCA.crt',
                'sudo /opt/cloudhsm/bin/configure -a ' + hsm_ip,
                'sudo /opt/cloudhsm/bin/configure --cmu ' + hsm_ip,
                ]


    returnData = {'Data':{}}
    
    while True:
        send_response = send_command(instanceId, commands, log_group)

        if send_response:
            returnData['Data']["CommandId"] = send_response['Command']['CommandId']
            break
        if context.get_remaining_time_in_millis() < 20000:
            raise Exception("Timed out attempting to send command to SSM")
        sleep(15) # nosemgrep
    
    if send_response:
        returnData['Data']["CommandId"] = send_response['Command']['CommandId']
        returnData['PhysicalResourceId'] = send_response['Command']['CommandId']

    return returnData

def onDelete(event, context):
    return False    

def isComplete(event, context):
    
    logger.info(event)
    request_type = event['RequestType']

    if request_type == 'Delete':
        return {'IsComplete': True}

    instanceId = event["ResourceProperties"]["InstanceId"]
    commandId = event['Data']["CommandId"]

    request_type = event['RequestType'] 

    while True:
        try:
            cmd_output_response = ssm.get_command_invocation(CommandId=commandId, InstanceId=instanceId)
            if cmd_output_response['Status'] == 'Success':
                return {'IsComplete': True}
            elif cmd_output_response['Status'] in ['Cancelled','TimedOut','Failed']:
                if cmd_output_response['StandardErrorContent']:
                    raise Exception("ssm command failed: " + cmd_output_response['StandardErrorContent'][:235])
                else:
                    raise Exception("ssm command failed: " + cmd_output_response['Status'])
            
            return {'IsComplete': False}  # Command is still running
        except ssm.exceptions.InvocationDoesNotExist:
            logger.debug('Invocation not available in SSM yet', exc_info=True)
        sleep(15)


def handler(event, context):

    logger.info(event)
    request_type = event['RequestType']
  
    if request_type == 'Create' : return onChange(event,context)
    if request_type == 'Update' : return onChange(event,context)
    if request_type == 'Delete' : return onDelete(event,context)

    return False

