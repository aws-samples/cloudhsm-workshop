from __future__ import print_function
import sys
sys.path.append('./dependencies')

import logging
from time import sleep
import boto3

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ssm = boto3.client('ssm')
secrets = boto3.client('secretsmanager')
hsm = boto3.client('cloudhsmv2')
from OpenSSL import crypto

def get_cluster_csr(cluster_id):
    response = hsm.describe_clusters(Filters={
        'clusterIds': [
            cluster_id,
            ]
        }
    )
    logger.info(response)

    return response['Clusters'][0]['Certificates']['ClusterCsr']
def generate_self_signed_certificate(key):
    cert = crypto.X509()
    cert.get_subject().C = "UK"
    cert.get_subject().ST = "Suffolk"
    cert.get_subject().L = "Ipswich"
    cert.get_subject().O = "Amazon"
    cert.get_subject().OU = "AWS"
    cert.get_subject().CN = "Demo Root Certificate (DO NOT TRUST ME)"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key)
    cert.sign(key, 'sha256')

    return cert

def sign_cluster_csr(csr=None, ca_key=None, ca_cert=None):
    # Load the CSR into openssl container
    csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

    # Build the certificate
    cert = crypto.X509()
    cert.set_serial_number(1001)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_subject(csr_obj.get_subject())
    cert.set_pubkey(csr_obj.get_pubkey())
    cert.sign(ca_key, 'sha256')

    return cert

def generate_rsa_key(key_len):
    logger.info("Generating RSA KEY")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, key_len)
    return key    

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

def onCreate(event, context):

    props = event['ResourceProperties']
    rsaSecret = props['RSASecret']
    selfSignedCert = props['SelfSignedCert']
    cluster_id = props['ClusterId']
    key = generate_rsa_key(2048)

    resp = secrets.put_secret_value(
        SecretId=rsaSecret,
        SecretString=crypto.dump_privatekey(crypto.FILETYPE_PEM,key).decode()
    )
    logger.info(resp)

    root_cert = generate_self_signed_certificate(key)


    csr = get_cluster_csr(
        cluster_id=cluster_id
        )    
    cluster_certificate = sign_cluster_csr(csr=csr, ca_key=key, ca_cert=root_cert)

    resp = hsm.initialize_cluster(
        ClusterId=cluster_id,
        SignedCert=crypto.dump_certificate(crypto.FILETYPE_PEM,cluster_certificate).decode(),
        TrustAnchor=crypto.dump_certificate(crypto.FILETYPE_PEM,root_cert).decode()
        )

    resp = ssm.put_parameter(
        Name=selfSignedCert,
        Value=crypto.dump_certificate(crypto.FILETYPE_PEM,root_cert).decode(),
        Overwrite=True
        )
    
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