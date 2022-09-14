from __future__ import print_function

import logging
import boto3
import datetime

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

ssm = boto3.client('ssm')
secrets = boto3.client('secretsmanager')
hsm = boto3.client('cloudhsmv2')
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

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
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(issuer)
    builder = builder.public_key(key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
    builder = builder.add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    )
    cert = builder.sign(key, hashes.SHA256())

    return cert

def sign_cluster_csr(csr=None, ca_key=None, ca_cert=None):
    one_day = datetime.timedelta(1, 0, 0)
    # Load the CSR into openssl container
    csr_obj = x509.load_pem_x509_csr(csr.encode('utf-8'))

    # Build the certificate
    builder = x509.CertificateBuilder()
    builder = builder.not_valid_before(datetime.datetime.today() - one_day)
    builder = builder.not_valid_after(datetime.datetime.today() + (one_day * 30))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(csr_obj.public_key())
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.subject_name(csr_obj.subject)
    builder = builder.add_extension(
      x509.SubjectAlternativeName(
        [x509.DNSName(u'cryptography.io')]
      ),
      critical=False
    )

    builder = builder.add_extension(
      x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    certificate = builder.sign(
      private_key=ca_key, algorithm=hashes.SHA256(),
    )
    
    return certificate

def generate_rsa_key(key_len):
    logger.info("Generating RSA KEY")
    key = rsa.generate_private_key(key_size=key_len,public_exponent=65537)
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
        SecretString=key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()).decode("UTF-8")
    )
    logger.info(resp)

    root_cert = generate_self_signed_certificate(key)
    csr = get_cluster_csr(
        cluster_id=cluster_id
        )    
    cluster_certificate = sign_cluster_csr(csr=csr, ca_key=key, ca_cert=root_cert)
    
    resp = hsm.initialize_cluster(
        ClusterId=cluster_id,
        SignedCert=cluster_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'),
        TrustAnchor=root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
        )
    logger.info(resp)

    resp = ssm.put_parameter(
        Name=selfSignedCert,
        Value=root_cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8'),
        Overwrite=True
        )
    logger.info(resp)
    
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