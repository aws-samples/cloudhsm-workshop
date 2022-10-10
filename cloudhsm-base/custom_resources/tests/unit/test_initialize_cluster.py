
from tests.unit import MOCK_CSR
from tests.unit.lambda_test_context import LambdaTestContext
import pytest
import boto3
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from initialize_cluster.lambda_function import generate_rsa_key
from initialize_cluster.lambda_function import generate_self_signed_certificate
from initialize_cluster.lambda_function import sign_cluster_csr


def test_generate_rsa_key():
    key = generate_rsa_key(2048)
    pem = key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("UTF-8")
    print(pem)
    assert key.key_size == 2048
    assert key.public_key().key_size == 2048
    assert key.public_key().public_numbers().e == 65537

def test_generate_self_signed_certificate():
    key = generate_rsa_key(2048)
    pem = key.public_key().public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo).decode("UTF-8")
    print(pem)

    pem = key.private_bytes(encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                            encryption_algorithm=serialization.NoEncryption()).decode("UTF-8")
    print(pem)
    assert key.key_size == 2048

    cert = generate_self_signed_certificate(key)
    pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode("UTF-8")
    print (pem)

    signed = sign_cluster_csr(MOCK_CSR,key,cert)

    pem = signed.public_bytes(encoding=serialization.Encoding.PEM).decode("UTF-8")
    print(pem)


    assert False